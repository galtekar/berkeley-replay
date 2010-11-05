#pragma once

#include "libvex_guest_x86.h"
#include "main_globals.h"
/* Helper routines for LibVEX. */

typedef VexGuestX86State TaskRegs;

#define VEX_eax      guest_EAX
#define VEX_ecx      guest_ECX
#define VEX_edx      guest_EDX
#define VEX_ebx      guest_EBX
#define VEX_esp      guest_ESP
#define VEX_ebp      guest_EBP
#define VEX_esi      guest_ESI
#define VEX_edi      guest_EDI
#define VEX_eip      guest_EIP
#define VEX_cs       guest_CS
#define VEX_ds       guest_DS
#define VEX_es       guest_ES
#define VEX_fs       guest_FS
#define VEX_gs       guest_GS
#define VEX_ss       guest_SS
#define VEX_op       guest_CC_OP
#define VEX_eflags   guest_CC_DEP1
#define VEX_dep2     guest_CC_DEP2
#define VEX_ndep     guest_CC_NDEP
#define VEX_CC_OP    guest_CC_OP
#define VEX_CC_DEP1  guest_CC_DEP1
#define VEX_DFLAG    guest_DFLAG
#define VEX_IDFLAG   guest_IDFLAG
#define VEX_ACFLAG   guest_ACFLAG
#define VEX_TFFLAG   guest_TFFLAG
#define VEX_GDT      guest_GDT
#define R(x) VEX_##x

typedef 
struct ArchStateStruct {
   /* --- BEGIN vex-mandated guest state --- */

   /* Saved machine context. */
   VexGuestX86State vex;

   /* Saved shadow context. */
   VexGuestX86State vex_shadow;

   /* Spill area. */
   UChar vex_spill[LibVEX_N_SPILL_BYTES];

   /* --- END vex-mandated guest state --- */

} 
TaskArchState;
