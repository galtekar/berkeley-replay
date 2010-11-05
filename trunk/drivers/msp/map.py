#!/usr/bin/env python2.6

while True:
   vaddr = int(raw_input(), 0)
   print "pgd_index:", vaddr >> 22
   print "pte_index:", (vaddr >> 12) & 0x3FF
