#! /usr/bin/perl

use strict;
my $proc=`ps aux|grep "tk"|grep -v "grep"|awk '{print \$2}'`;
#my $proc=`ps aux|grep "valgrind"|grep -v "grep"|awk '{print \$2}'`;
my @lines=split(/\n/,$proc);
foreach my $line (@lines){
	print $line. "\n";
	$line=~s/^[\s]+//;
	chomp($line);
#	my @tmp=split(/\s/,$line);
	print("kill $line\n");
	system("kill $line");
}