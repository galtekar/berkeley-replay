#!/usr/bin/gawk -f

BEGIN { 
}

/\[Prof\]/ {

   nr_cnstr = $6;

   dso_nr_insn[$4] += 1;
   dso_sum[$4] += nr_cnstr;

   if (nr_cnstr > 0) {
      dso_nr_active[$4] += 1;
      
      addr = 0x8048000 + $5
      cmd = "addr2line -C -f -e " $4 " " hex(addr) " | line";
      print $4, $5, cmd, nr_cnstr
      system(cmd);
   }

}

END { 
   nr_insn = 0;
   sum = 0;
   nr_active = 0;

   for (dso in dso_nr_insn) {
      avg_cnstr_per_insn = 0.0;

      print dso;
      print "  total static insns =", dso_nr_insn[dso];
      print "  total gen. const. =", dso_sum[dso];
      printf("  active static insns = %d (%f %%)\n",
             dso_nr_active[dso],
             dso_nr_active[dso]/dso_nr_insn[dso]*100);
      if (dso_nr_active[dso]) {
         avg_cnstr_per_insn = dso_sum[dso] / dso_nr_active[dso];
      }
      printf("  avg. constr. size = %f\n", avg_cnstr_per_insn);

      nr_insn += dso_nr_insn[dso];
      sum += dso_sum[dso];
      nr_active += dso_nr_active[dso];
   }

   print "----- Entire path -----";
   print "  total static insns =", nr_insn;
   print "  total gen. const. =", sum;
   printf("  active static insns = %d (%f %%)\n",
          nr_active,
          nr_active/nr_insn*100);
   printf("  avg. constr. size = %f\n", sum / nr_active);
}
