#! /usr/bin/perl
#Executes command in the directory on the machines specified in topology/map

use strict;
use Getopt::Std;
my %options;
if(@ARGV<4){
	print "$0 <topology file> <map file> <top directory> <command>\n";
	die;
}

my $single=0;
my $profile=0;
getopts("l:d:sp",\%options);
if(defined $options{s}){
	$single=1;
}
if(defined $options{p}){
	$profile=1;
}

print "Profile:$profile\n";
my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];
my $topdir=$ARGV[2];
my $command=$ARGV[3];
my %map=();
my %hostmap=();
my $username="sriram_s";
my $remotedir=$topdir;
my $cluster=`hostname`;
#print "Cluster:".$cluster."\n";
$cluster=substr($cluster,0,1);
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
		if ($hostmap{$idValue}!~/^$cluster/){
			next;
		}

		if ($idValue == $nodes-1 && $single==1){
			my $delay=120;
			if ($nodes >= 50){
				$delay=120;
			}	
			sleep($delay);
		}
		my $value=$map{$idValue};
		my $host=$hostmap{$idValue};
		my $dirname="exp.".$value;	
		$dir=$topdir."/".$dirname;
		print("ssh $username\@$host \" cd $remotedir/$dirname;$command \" &\n");
		system("ssh $username\@$host \" cd $remotedir/$dirname;$command \" &");
		if ($profile){
			print "HERE\n";
			my $profileCommand="nohup \./scripts/profile_mem.pl &";
			print("ssh $username\@$host \" cd $remotedir/$dirname;$profileCommand \" &\n");
			system("ssh $username\@$host \" cd $remotedir/$dirname;$profileCommand \" &");
		}
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
