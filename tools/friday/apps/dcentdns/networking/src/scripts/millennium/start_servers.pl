#! /usr/bin/perl

#Starts up servers on a set of  millennium machines
use strict;
use Getopt::Std;
my %options;
if(@ARGV<2){
	print "$0 -s -p <topology file> <map file>\n";
	print "Starts up a set of servers on the millennium cluster\n";
	print "-s	Starts a single instance at a later time\n";
	print "-p 	Profiles memory usage\n";
	die;
}
my $singleFlag="";
my $profileFlag="";
getopts("sp",\%options);
if(defined $options{s}){
	$singleFlag=" -s";
}
if(defined $options{p}){
	$profileFlag=" -p";
}
my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];
my %map=();
my %hostmap=();
my $username="sriram_s";
my $remotedir="dev";
my $topdir=`pwd`;
my $dir="";
chomp($topdir);
init_map($mapFile,\%map,\%hostmap);

#Create the config files
print("$topdir/scripts/make_lfile.pl $topologyFile $mapFile\n");
system("$topdir/scripts/make_lfile.pl $topologyFile $mapFile");
open(FILE,$topologyFile);

#Launch the servers on the speciifed nodes
#my $cmd="nohup valgrind --leak-check=yes ./server config.txt &>er &";
my $cmd="nohup ./tk config.txt &";
print("./scripts/millennium/exec.pl $singleFlag $profileFlag $topologyFile $mapFile $topdir $cmd\n");
system("./scripts/millennium/exec.pl $singleFlag $profileFlag $topologyFile $mapFile $topdir \"$cmd\"");

#Create an association of ID numebers and IP:PORT
sub init_map(){
	my $mapFile=$_[0];
	my %map;
	my %hostmap;
	open(FILE,$mapFile) or die "Cannot open $mapFile\n";
	my @lines=<FILE>;
	foreach my $line (@lines){
		my ($key,$value)=split(/=/,$line);
		chomp($value);
		my $newValue=$key."-".$value;
		$newValue=~s/:/-/g;
		$map{$key}=$newValue;
		my ($host,$port)=split(/-/,$value);
		$hostmap{$key}=$host;
	}

	%{$_[1]}=%map;
	%{$_[2]}=%hostmap;
}
