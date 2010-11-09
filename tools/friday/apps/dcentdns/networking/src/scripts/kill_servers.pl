#! /usr/bin/perl

use strict;
use Getopt::Std;
my %options;
my $remotedir="/home/ucb_i3/galtekar/dcentdns";
if(@ARGV<2){
	print "$0 <topology file> <map file>\n";
	die;
}
my $username;
getopts("l:",\%options);
if (defined $options{l}){
	$username=$options{l};
}else{
	$username="ucb_i3";
}
my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];

my $cmd="./scripts/kill.pl";
system("./scripts/exec.pl -d $remotedir -l $username $topologyFile $mapFile \"$cmd\"");

