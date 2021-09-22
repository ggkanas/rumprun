/*
 * Copyright (C) 2019 Waldemar Kozaczuk
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <arch/amd64/vmlinux.h>

#include <assert.h>
#include <hw/types.h>
#include <hw/multiboot.h>

#define RUMP_MULTI_BOOT_INFO_ADDR      0x1000
#define RUMP_E820_TABLE_ADDR           0x2000

//
// Instead of defining full boot_params and setup_header structs as in
// Linux source code, we define only handful of offsets pointing the fields
// we need to read from there. For details please this chunk of Linux code -
// https://github.com/torvalds/linux/blob/b6839ef26e549de68c10359d45163b0cfb031183/arch/x86/include/uapi/asm/bootparam.h#L151-L198
#define LINUX_KERNEL_BOOT_FLAG_MAGIC  0xaa55
#define LINUX_KERNEL_HDR_MAGIC        0x53726448 // "HdrS"

#define SETUP_HEADER_OFFSET  0x1f1   // look at bootparam.h in linux
#define SETUP_HEADER_FIELD_VAL(boot_params, offset, field_type) \
    (*(field_type*) (boot_params + SETUP_HEADER_OFFSET + offset))

#define BOOT_FLAG_OFFSET     sizeof(uint8_t) + 4 * sizeof(uint16_t) + sizeof(uint32_t)
#define HDR_MAGIC_OFFSET     sizeof(uint8_t) + 6 * sizeof(uint16_t) + sizeof(uint32_t)

#define E820_ENTRIES_OFFSET  0x1e8   // look at bootparam.h in linux
#define E820_TABLE_OFFSET    0x2d0   // look at bootparam.h in linux

#define CMD_LINE_PTR_OFFSET  sizeof(uint8_t) * 5 + sizeof(uint16_t) * 11 + sizeof(uint32_t) * 7

struct linux_e820ent {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));

// When OSv kernel gets booted directly as 64-bit ELF (loader.elf) as it is
// the case on firecracker we need a way to extract all necessary information
// about available memory and command line. This information is provided
// the struct boot_params (see details above) placed in memory at the address
// specified in the RSI register.
// The following extract_linux_boot_params() function is called from
// entry64 in boot.S and verifies OSV was indeed boot as Linux and
// copies memory and cmdline information into OSv multiboot struct.
// Please see https://www.kernel.org/doc/Documentation/x86/boot.txt for details
// of Linux boot protocol. Bear in mind that OSv implements very narrow specific
// subset of the protocol as assumed by firecracker.
extern void extract_linux_boot_params(void *boot_params)
{   //
    // Verify we are being booted as Linux 64-bit ELF kernel

    assert( SETUP_HEADER_FIELD_VAL(boot_params, BOOT_FLAG_OFFSET, uint16_t) == LINUX_KERNEL_BOOT_FLAG_MAGIC);
    assert( SETUP_HEADER_FIELD_VAL(boot_params, HDR_MAGIC_OFFSET, uint32_t) == LINUX_KERNEL_HDR_MAGIC);

    // Set location of multiboot info struct at arbitrary place in lower memory
    // to copy to (happens to be the same as in boot16.S)
    struct multiboot_info* mb_info = (struct multiboot_info*)(RUMP_MULTI_BOOT_INFO_ADDR);


    //Set flags based on what fields are used
    //would be 0000 0010 0100 1111 in qemu
    //mb_info->flags = 0x024f;
    //we use 0000 0000 0100 1101
    mb_info->flags = 0x004d;



    // Copy command line pointer from boot params
    mb_info->cmdline = SETUP_HEADER_FIELD_VAL(boot_params, CMD_LINE_PTR_OFFSET, uint32_t);



    //Set mod count to zero
    mb_info->mods_count = 0;

    // Copy e820 information from boot params
    mb_info->mmap_length = 0;
    mb_info->mmap_addr = RUMP_E820_TABLE_ADDR;

    struct linux_e820ent *source_e820_table = (struct linux_e820ent *)(boot_params + E820_TABLE_OFFSET);
    struct multiboot_mmap_entry *dest_e820_table = (struct multiboot_mmap_entry *)(uint64_t)(mb_info->mmap_addr);

    uint8_t en820_entries = *(uint8_t*)(boot_params + E820_ENTRIES_OFFSET);
    for (int e820_index = 0; e820_index < en820_entries; e820_index++) {
        dest_e820_table[e820_index].size = 20;
        dest_e820_table[e820_index].type = source_e820_table[e820_index].type;
        dest_e820_table[e820_index].addr = source_e820_table[e820_index].addr;
        dest_e820_table[e820_index].len = source_e820_table[e820_index].size;
        mb_info->mmap_length += sizeof(struct multiboot_mmap_entry);
    }



    /*auto now = processor::ticks();
    u32 now_high = (u32)(now >> 32);
    u32 now_low = (u32)now;

    mb_info->tsc_init_hi = now_high;
    mb_info->tsc_init = now_low;

    mb_info->tsc_disk_done_hi = now_high;
    mb_info->tsc_disk_done = now_low;

    mb_info->tsc_uncompress_done_hi = now_high;
    mb_info->tsc_uncompress_done = now_low;*/
    return;
}
