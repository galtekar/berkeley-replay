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
init_map($mapFile,\%map,\%hostmap);

system("$topdir/scripts/make_lfile.pl $topologyFile $mapFile");
open(FILE,$topologyFile);
my @lines=<FILE>;

my $cmd="if [[ ! -d $remotedir ]];then mkdir -p $remotedir;fi";
system("$topdir/scripts/exec.pl -l $username $topologyFile $mapFile \"$cmd\"\n");

foreach my $line (@lines){
	if($line=~/^id/ ){
		my ($key,$idValue)=split(/=/,$line);
		chomp($idValue);
		my $value=$map{$idValue};
		my $host=$hostmap{$idValue};
		my $dirname="exp.".$value;	
		$dir=$topdir."/".$dirname;
		print "Copying to destination: $username\@$host:$remotedir\n";
		system("scp -r $dirname $username\@$host:$remotedir");
	}
}
my $cmd="nohup ./tk config.txt &";
system("$topdir/scripts/exec.pl -d $remotedir -l $username $topologyFile $mapFile \'$cmd\'\n");
my $cmd="nohup ./dns_launcher.pl dns_config.txt";
system("$topdir/scripts/exec.pl -d $remotedir -l $username $topologyFile $mapFile \'$cmd\'\n");

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
