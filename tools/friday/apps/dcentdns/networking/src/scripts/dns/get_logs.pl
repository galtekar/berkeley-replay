#! /usr/bin/perl

use strict;
use Getopt::Std;
my %options;
my $remotedir;
my $topdir=`pwd`;
chomp($topdir);
my $scriptdir = "scripts/dns";
my $username="sriram_s";

if(@ARGV<2){
	print "$0 [options] <topology file> <map file>\n";
	print "-d 	Remote working directory\n";
	print "-l 	Username\n";
	die;
}
getopts("l:d:",\%options);
if (defined $options{l}){
	$username=$options{l};
}
if (defined $options{d}){
	$remotedir=$options{d};
}else{
	$remotedir="/work/sriram_s/dev/networking/src";
}

my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];
my %map=();
my %hostmap=();


chomp($topdir);
init_map($mapFile,\%map,\%hostmap);

open(FILE,$topologyFile);
my @lines=<FILE>;
foreach my $line (@lines){
	if($line=~/^id/ ){
		my ($key,$idValue)=split(/=/,$line);
		chomp($idValue);
		my $value=$map{$idValue};
		my $host=$hostmap{$idValue};
		my $dirname="exp.".$value;	
		print("rsync -avz -e ssh $username\@$host:$remotedir/$dirname/log.* $dirname\n");
		system("rsync -avz -e ssh $username\@$host:$remotedir/$dirname/log.* $dirname");
	}
}
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
