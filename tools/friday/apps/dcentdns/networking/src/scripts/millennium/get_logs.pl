#! /usr/bin/perl

use strict;
if(@ARGV<2){
	print "$0 <topology file> <map file>\n";
	die;
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


open(FILE,$topologyFile);
my @lines=<FILE>;
foreach my $line (@lines){
	if($line=~/^id/ ){
		my ($key,$idValue)=split(/=/,$line);
		chomp($idValue);
		my $value=$map{$idValue};
		my $host=$hostmap{$idValue};
		my $dirname="exp.".$value;	
		$dir=$topdir."/".$dirname;
		print("scp $username\@$host:./$remotedir/$dirname/log.* $dirname\n");
		system("scp $username\@$host:./$remotedir/$dirname/log.* $dirname");
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
