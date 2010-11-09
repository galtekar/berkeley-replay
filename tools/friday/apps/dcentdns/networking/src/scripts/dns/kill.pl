#! /usr/bin/perl

use strict;
my $killFlags="-9";

my $proc=`ps aux|grep "codonssecureserver"|grep -v "grep"|awk '{print \$2}'`;
terminate ($proc);
$proc=`ps aux|grep "tk"|grep -v "grep"|awk '{print \$2}'`;
terminate ($proc);
$proc=`ps aux|grep "profile_mem"|grep -v "grep"|awk '{print \$2}'`;
terminate ($proc);

sub terminate{
	my $proc=shift @_;
	my @lines=split(/\n/,$proc);
	foreach my $line (@lines){
#		print $line. "\n";
		$line=~s/^[\s]+//;
		chomp($line);
#	my @tmp=split(/\s/,$line);
		print("kill $killFlags $line\n");
		system("kill $killFlags $line");
	}
}
