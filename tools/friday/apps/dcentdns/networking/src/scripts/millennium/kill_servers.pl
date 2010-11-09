#! /usr/bin/perl

use strict;
my $topdir=`pwd`;
chomp($topdir);

if(@ARGV<2){
	print "$0 <topology file> <map file>\n";
	die;
}
my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];

my $cmd="../scripts/millennium/kill.pl";
print("./scripts/millennium/exec.pl $topologyFile $mapFile $topdir $cmd\n");
system("./scripts/millennium/exec.pl $topologyFile $mapFile $topdir \"$cmd\"");

