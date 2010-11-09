#! /usr/bin/perl

use strict;
use Getopt::Std;
my %options;
my $remotedir;
my $topdir=`pwd`;
chomp($topdir);
my $scriptdir="scripts/dns";
my $username="ucb_i3";

if(@ARGV<2){
	print "$0 [options] <topology file> <map file>\n";
	print "-l <username>\n";
	print "-d <remote directory>\n";
	die;
}
getopts("l:d:",\%options);
if (defined $options{l}){
	$username=$options{l};
}
if (defined $options{d}){
	$remotedir=$options{d};
}else{
	$remotedir="/home/ucb_i3/galtekar/dcentdns";
}
my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];

my $cmd="${scriptdir}/kill.pl";
print("${topdir}/${scriptdir}/exec.pl -d $remotedir -l $username $topologyFile $mapFile $cmd\n");
system("${topdir}/${scriptdir}/exec.pl -d $remotedir -l $username $topologyFile $mapFile \"$cmd\"");

