#! /usr/bin/perl

use strict;
use Getopt::Std;
my %options;

if(@ARGV<3){
	print "$0 <topology file> <map file> <command>\n";
	die;
}
my $username;
my $remotedir;
my $single=0;
getopts("l:d:s",\%options);
if (defined $options{l}){
	$username=$options{l};
}else{
	$username="ucb_i3";
}
if (defined $options{d}){
	$remotedir=$options{d};
}else{
	$remotedir="/home/ucb_i3/galtekar/dcentdns";
}
if(defined $options{s}){
	$single=1;
}
my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];
my $command=$ARGV[2];
my %map=();
my %hostmap=();

my $topdir=`pwd`;
my $dir="";


chomp($topdir);
init_map($mapFile,\%map,\%hostmap);

open(FILE,$topologyFile);
my @lines=<FILE>;
my $nodes=0;
foreach my $line (@lines){
	if($line=~/^id/ ){
		$nodes++;
	}
}

foreach my $line (@lines){
	if($line=~/^id/ ){
		my ($key,$idValue)=split(/=/,$line);
		chomp($idValue);
		if ($idValue == $nodes-1 && $single==1){
			sleep(20);
		}
		my $value=$map{$idValue};
		my $host=$hostmap{$idValue};
		my $dirname="exp.".$value;	
		$dir=$topdir."/".$dirname;
		print("ssh $username\@$host \" cd $remotedir/$dirname;$command \" &\n");
		system("ssh $username\@$host \" cd $remotedir/$dirname;$command \" >& out.$idValue &");
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
		$map{$key}=$value;
		my ($host,$port)=split(/_/,$value);
		$hostmap{$key}=$host;
	}

	%{$_[1]}=%map;
	%{$_[2]}=%hostmap;
}
