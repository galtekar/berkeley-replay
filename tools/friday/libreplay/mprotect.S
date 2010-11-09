.file "mprotect.S"
.globl old_esp
	.bss
	.align 4
	.type old_esp, @object
	.size old_esp, 4
old_esp:
	.zero 4
.globl old_ebp
	.bss
	.align 4
	.type old_ebp, @object
	.size old_ebp, 4
old_ebp:
	.zero 4

.text
.globl mprotect_remove
	.type mprotect_remove, @function
mprotect_remove:
	movl %esp, old_esp
	movl %ebp, old_ebp
	movl alt_stack, %esp
	movl alt_stack, %ebp

	pusha	# Save all registers.
	pushf

	movl $1, %edx # 3rd arg: protections
	movl $4096, %ecx # 2nd arg: size
	movl page_start_addr, %ebx # 1st arg: address

	andl $-4096, %ebx # align it to a page boundary
	
	movl $125, %eax # mprotect syscall number.

	int $0x80 # syscall

	popf
	popa # restore all registers

	movl old_esp, %esp # restore the stack
	movl old_ebp, %ebp
	int $0x3

.globl mprotect_restore
	.type mprotect_restore, @function
mprotect_restore:
	movl %esp, old_esp
	movl %ebp, old_ebp
	movl alt_stack, %esp
	movl alt_stack, %ebp

	pusha	# Save all registers.
	pushf

	movl $3, %edx # 3rd arg: protections
	movl $4096, %ecx # 2nd arg: size
	movl page_start_addr, %ebx # 1st arg: address

	andl $-4096, %ebx # align it to a page boundary

	movl $125, %eax # mprotect syscall number.

	int $0x80 # syscall

	popf
	popa # restore all registers

	movl old_esp, %esp # restore the stack
	movl old_ebp, %ebp
	int $0x3
