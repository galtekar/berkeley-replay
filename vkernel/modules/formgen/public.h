/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#pragma once

extern int 
Cgen_GetRegByte(const struct Task *tsk_ptr, off_t regOff, 
      struct StateByte *sbP);

extern int
Cgen_GetMemByte(const struct Task *tsk_ptr, const void *srcP, 
      struct StateByte *sbP);


extern int
Cgen_GetTaintMap(const struct Task *tsk_ptr, const void *base_ptr,
                 const size_t len, char *taint_map);

extern void
Cgen_TaintMemRegion(const void *base_ptr, const size_t len);

extern int  Cgen_AddPtrRegion(const ulong start, const size_t len);

extern int  Cgen_RmPtrRegion(const int id);
