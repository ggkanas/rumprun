/*-
 * Copyright (c) 2014, 2015 Antti Kantee.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <hw/kernel.h>
#include <hw/multiboot.h>

#define MYMULTIBOOT_FLAGS \
    (MULTIBOOT_PAGE_ALIGN | MULTIBOOT_MEMORY_INFO | MULTIBOOT_AOUT_KLUDGE)

.section .bootstrap, "ax"

.code32

.align 4
bootstrap:
.long MULTIBOOT_HEADER_MAGIC
.long MYMULTIBOOT_FLAGS
.long -(MULTIBOOT_HEADER_MAGIC+MYMULTIBOOT_FLAGS)
.long bootstrap
.long 0x100000
.long _edata
.long _ebss
.long _start

.space 4096
bootstack:

/*
 * Bootloader entry point.
 *
 * Bootstrap is slightly different from i386.  Multiboot puts us only
 * in 32bit mode, so it's our responsibility to install a page table
 * and switch to long mode.  Notably, we can't call C code until
 * we've switched to long mode.
 */
ENTRY(_start)
	cld
	movl $bootstack, %esp

    /* save multiboot info pointer at top of stack, we pop it in 64bit */
    pushl $0
    pushl %ebx



	/* save BIOS data area values */
	movw BIOS_COM1_BASE, %bx
	movw %bx, bios_com1_base
	movw BIOS_CRTC_BASE, %bx
	movw %bx, bios_crtc_base

	/* clear console */
	pushl %eax
	movw $' ', %ax
	movl $(CONS_ADDRESS), %edi
	movl $(CONS_WIDTH*CONS_HEIGHT), %ecx
	rep stosw
	popl %eax

	/* only multiboot is supported for now */
	cmpl $MULTIBOOT_BOOTLOADER_MAGIC, %eax
	jne nomultiboot

	lgdt (gdt64_ptr)
	pushl $0x0
	pushw $0x10
	pushl $1f
	lret

1:	movl $0x18, %eax
	movl %eax, %ds
	movl %eax, %es
	movl %eax, %ss

	xorl %eax, %eax
	movl %eax, %fs
	movl %eax, %gs

	/*
	 * x86_64 switch to long mode
	 */

	/* 1: enable pae and sse */
	movl %cr4, %eax
	orl $(CR4_OSXMMEXCPT|CR4_OSFXSR|CR4_PAE), %eax
	movl %eax, %cr4

	/* 2: enable long mode */
	movl $MSR_EFER, %ecx
	rdmsr
	movl $MSR_EFER_LME, %eax
	wrmsr

	/* 3: load pml4 pointer */
	movl $cpu_pml4, %eax
	movl %eax, %cr3

	/* 4: enable paging */
	movl %cr0, %eax
	orl $(CR0_PG|CR0_WP|CR0_PE), %eax
	movl %eax, %cr0



	/* 5: poetically longjump to longmode */
    pushw $0x08
    pushl $_start64
    lret

	/* NOTREACHED */
	jmp haltme

nomultiboot:
	/* we don't have printf available yet, just output manually */
	mov $nomultimesg, %ebx
	mov $(CONS_ADDRESS), %ecx
1:
	movsbl (%ebx), %eax
	test %al, %al
	je haltme
	orl $0x500, %eax
	movl %eax, (%ecx)
	inc %ebx
	addl $2, %ecx
	jmp 1b

haltme:
	cli
	hlt
	jmp haltme
END(_start)

nomultimesg:
	.asciz "not multibooted, halting!"

#include "pagetable.S"

/*
 * amd64 programmer's manual:
 *
 * "In long mode, segmentation is not used ... except for a few exceptions."
 *
 * Uuuyea, exceptions.
 */

.data
.org 0x500
.align 64
.globl cpu_gdt64
cpu_gdt64:
	.quad 0x0000000000000000
	.quad 0x00af9b000000ffff	/* 64bit CS		*/
	.quad 0x00cf9b000000ffff	/* 32bit CS		*/
	.quad 0x00cf93000000ffff	/* DS			*/
	.quad 0x0000000000000000	/* TSS part 1 (via C)	*/
	.quad 0x0000000000000000	/* TSS part 2 (via C)	*/
gdt64_end:
.align 64

.type gdt64_ptr, @object
gdt64_ptr:
	.word gdt64_end-cpu_gdt64-1
	.quad cpu_gdt64
test_str:
    .asciz "This is a message\n"

.code64

ENTRY(_start64_from_linux)
    cld
    mov $bootstack, %rsp

    /* _start64 looks for the multiboot info pointer in the boot stack
       extract_linux_boot_params assumes the pointer is at 0x1000 */
    push $0x1000

    /* save BIOS data area values */
    movw $0x3f8, %bx
    movw %bx, bios_com1_base
    movw $0x0, %bx
    movw %bx, bios_crtc_base
    movw bios_com1_base, %bx

    /* clear console */
	push %rax
	movw $' ', %ax
	mov $(CONS_ADDRESS), %rdi
	mov $(CONS_WIDTH*CONS_HEIGHT), %rcx
	rep stosw
	pop %rax

    lgdt (gdt64_ptr)

1:	movl $0x18, %eax
	movl %eax, %ds
	movl %eax, %es
	movl %eax, %ss

	xorl %eax, %eax
	movl %eax, %fs
	movl %eax, %gs

    /* 1: enable pae and sse */
    movq %cr4, %rax
    orl $(CR4_OSXMMEXCPT|CR4_OSFXSR|CR4_PAE), %eax
    movq %rax, %cr4

    /* 3: load pml4 pointer */
    movq $cpu_pml4, %rax
    movq %rax, %cr3

    /* 4: enable paging */
    movq %cr0, %rax
    orl $(CR0_PG|CR0_WP|CR0_PE), %eax
    movq %rax, %cr0


    mov %rsi, %rdi
    call extract_linux_boot_params

    jmp _start64
    hlt
END(_start64_from_linux)


ENTRY(_start64)
	movq $bootstack, %rsp
	xorq %rbp, %rbp

	/* read multiboot info pointer */
	movq -8(%rsp), %rdi

	pushq $0x0
	pushq $0x0

	call x86_boot
	hlt
END(_start64)

ENTRY(amd64_lidt)

	lidt (%rdi)

	ret
END(amd64_lidt)

ENTRY(amd64_ltr)
	ltr %di
	ret
END(amd64_ltr)
