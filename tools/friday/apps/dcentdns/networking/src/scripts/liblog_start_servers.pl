#! /usr/bin/perl

use strict;
use Getopt::Std;
my %options;
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
my $dnsDir="../../djbdns";
my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];
my %map=();
my %hostmap=();
my $remotedir="/home/ucb_i3/galtekar/dcentdns";
my $topdir=`pwd`;
my $dir="";

chomp($topdir);

my $cmd="nohup /home/ucb_i3/galtekar/remote_package/liblog ./tk config.txt &";
#my $cmd="nohup ./tk config.txt &";
system("$topdir/scripts/exec.pl -d $remotedir -l $username $topologyFile $mapFile \'$cmd\'\n");
#sleep(3);
#my $cmd="nohup ./dns_launcher.pl dns_config.txt &";
#system("$topdir/scripts/exec.pl -d $remotedir -l $username $topologyFile $mapFile \'$cmd\'\n");
