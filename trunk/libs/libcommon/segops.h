#pragma once

struct LinuxSegmentDesc {
   unsigned int  entry_number;
   unsigned long base_addr;
   unsigned int  limit;
   unsigned int  seg_32bit: 1;
   unsigned int  contents: 2;
   unsigned int  read_exec_only: 1;
   unsigned int  limit_in_pages: 1;
   unsigned int  seg_not_present: 1;
   unsigned int  useable: 1;
};

extern void
SegOps_InitDesc(struct LinuxSegmentDesc *desc_ptr, int entry_no,
               ulong start_addr, size_t len, int prot);


extern int
SegOps_InstallInLDT(struct LinuxSegmentDesc *desc_ptr);

void
SegOps_SetReg(int reg, int entry_no);
