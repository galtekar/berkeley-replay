{
   split($0, fields, " ");
   addr_str = substr(fields[3], 1, index(fields[3], ":")-1);
   if (addr_str < "0x9000000") print addr_str, fields[4];
}
