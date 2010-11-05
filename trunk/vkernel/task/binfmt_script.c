/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

int
Script_Load(struct LinuxBinPrm *bprm, TaskRegs *regs)
{
   int err;
   char interp[BINPRM_BUF_SIZE];
   char *cp, *i_name, *i_arg;
   struct FileStruct *filp = bprm->file;

   ASSERT(filp);
  
   if ((bprm->buf[0] != '#') || (bprm->buf[1] != '!') || (bprm->sh_bang)) {
      DEBUG_MSG(5, "Not a script.\n");
      return -ENOEXEC;
   }


   DEBUG_MSG(5, "We have a script: sh_bang=%d\n", bprm->sh_bang);
   bprm->sh_bang++;

   /*
    * This section does the #! interpretation.
	 * Sorta complicated, but hopefully it will work.  -TYT
	 */
   
	if ((cp = strchr(bprm->buf, '\n')) == NULL)
		cp = bprm->buf+BINPRM_BUF_SIZE-1;
	*cp = '\0';
	while (cp > bprm->buf) {
		cp--;
		if ((*cp == ' ') || (*cp == '\t'))
			*cp = '\0';
		else
			break;
	}
	for (cp = bprm->buf+2; (*cp == ' ') || (*cp == '\t'); cp++);
	if (*cp == '\0') 
		return -ENOEXEC; /* No interpreter name found */
	i_name = cp;
	i_arg = NULL;
	for ( ; *cp && (*cp != ' ') && (*cp != '\t'); cp++)
		/* nothing */ ;
	while ((*cp == ' ') || (*cp == '\t'))
		*cp++ = '\0';
	if (*cp)
		i_arg = cp;
	strcpy (interp, i_name);

	/*
	 * OK, we've parsed out the interpreter name and
	 * (optional) argument.
	 * Splice in (1) the interpreter's name for argv[0]
	 *           (2) (optional) argument to interpreter
	 *           (3) filename of shell script (replace argv[0])
	 *
	 * This is done in reverse order, because of how the
	 * user environment and arguments are stored.
	 */
	Exec_RemoveArgZero(bprm);
	err = Exec_CopyStringsKernel(1, &bprm->interp, bprm);
	if (err < 0) return err; 
	bprm->argc++;
	if (i_arg) {
		err = Exec_CopyStringsKernel(1, &i_arg, bprm);
		if (err < 0) return err; 
		bprm->argc++;
	}
	err = Exec_CopyStringsKernel(1, &i_name, bprm);
	if (err) return err; 
	bprm->argc++;
	bprm->interp = interp;


   File_Put(bprm->file);
   bprm->file = NULL;

   filp = Exec_Open(interp);
   if (IS_ERR(filp)) {
      return PTR_ERR(filp);
   }
   bprm->file = filp;
   err = Exec_PrepareBprm(bprm);
   ASSERT_UNIMPLEMENTED(!err);
   return Exec_SearchBinaryHandler(bprm, regs);
}
