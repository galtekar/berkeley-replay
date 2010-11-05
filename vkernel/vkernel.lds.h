/*
 * Copyright (C) 2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */

#pragma once

#define SYM2ADDR(name) ({ extern ulong name; (ulong)&name; })

#define __LINUX_KERNEL_START     0xc0000000UL
#define __LINUX_VDSO_START       0xffffe000UL
#define __LAST_PAGE              0xfffff000UL

#define __LINUX_VDSO_SIZE        PAGE_SIZE

/* XXX: if we make the vkernel PIC (which we probably should if we
 * want to make the vkernel itself replayable), these should be made 
 * offsets rather than absolute addresses. */

/* 
 * Why place the kernel here?
 *
 * We need about 654MB of address-space (yikes!) for all vkernel data.
 * Unfortunately, 0xb0000000 to 0xffffffff is used by Linux
 * for vdso, stack (which we don't use), and kernel code. 
 * So we can't use that. Do the math.
 */
#define __IMAGE_START            0x90000000

/* All sections are offset relative to __IMAGE_START. */
#define __VDSO_TEXT_START        SYM2ADDR(__vdso_text_start)
#define __VDSO_TEXT_END          SYM2ADDR(__vdso_text_end)
#define __VKERNEL_TEXT_START     SYM2ADDR(__kernel_text_start)
#define __VKERNEL_TEXT_END       SYM2ADDR(__kernel_text_end)
#define __TDATA_START            SYM2ADDR(__tdata_start)
#define __TDATA_END              SYM2ADDR(__tdata_end)
#define __TLS_SIZE               SYM2ADDR(__tls_size)
#define __SHAREDAREA_HEAP_START  SYM2ADDR(__sharedarea_heap_start)
/* This gives almost 256MB of sharedarea heap! Race-detection needs this. */
#define __SHAREDAREA_HEAP_END    (__IMAGE_START+0x10000000UL)
#define __TC_START               __SHAREDAREA_HEAP_END
#define __TC_END                 (__IMAGE_START+0x12000000UL)
#define __VCPU_LOGS_START        __TC_END
/* 
 * Why not start the vperfctr page at the very end?
 *
 * Because we gotta leave enough room for the per-task perfctr *pages*. 
 * Yes, pages plural, since the branch count is virtualized per-task, 
 * not per-vcpu. XXX: should be per-vcpu, but'll take Linux kernel work.
 */
#define __VCPU_LOGS_END          (__IMAGE_START+0x22000000UL)
#define __VPERFCTR_START         __VCPU_LOGS_END
#define __VPERFCTR_END           (__IMAGE_START+0x27000000UL)
#define __IMAGE_END              __VPERFCTR_END

#define __IMAGE_LEN              (__IMAGE_END - __IMAGE_START)


/* ---- Static checks. ---- */

#if PAGE_SIZE == 0
#error "invalid page size"
#endif

#if __IMAGE_START >= __IMAGE_END
#error "invalid image start/end"
#endif

#if __IMAGE_LEN > 0x40000000UL
#error "image is too large"
#endif

#if __IMAGE_END > __LINUX_KERNEL_START
#error "vkernel maps over the Linux kernel!"
#endif

#if ((__VPERFCTR_END - __VPERFCTR_START)/PAGE_SIZE) < 1024
#error "not enough room for per-task vperfctr pages"
#endif
