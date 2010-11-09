#! /usr/bin/perl
#
my $time=2;
my $user="galtekar";
use strict;
open (FILE,">mem.prof") or die "Could not open mem.prof\n";
for(;;){
	#my $out=`top -b -n 1|grep -E " server"|grep -v grep`;
	my $out1=`ps -u $user -o pid,pmem,rssize,vsize,etime,cmd|grep -E "tk"|grep -v grep`;
	my $out2=`ps -u $user -o pid,pmem,rssize,vsize,etime,cmd|grep -E "codons"|grep -v grep`;
	if ($out1 eq ""|| $out2 eq ""){
		last;
	}
	print FILE $out1;
	print FILE $out2;
	sleep $time;
}
close FILE;
