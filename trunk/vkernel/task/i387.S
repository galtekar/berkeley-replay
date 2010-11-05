/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
.file "i387.S"

.globl Task_Savei387
.type Task_Savei387, @function
Task_Savei387:
   movl        4(%esp), %eax

   /* 
    * In addition to saving the FP environment, FNSTENV
    * masks all floating-point expception (because this instr
    * is intended for use in signal handlers).
    */
   fnstenv     (%eax)
  
   /*
    * Restore the pre-FNSTENV floating-point mask.
    */
   fldenv      (%eax)

   movl        $0, %eax
.size Task_Savei387, .-Task_Savei387
