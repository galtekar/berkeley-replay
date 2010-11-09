#! /usr/bin/perl

use strict;
use Getopt::Std;
my %options;
my $remotedir;
my $username="ucb_i3";
my $singleFlag="";
my $profileFlag="";

if(@ARGV<4){
	print "$0 -s -p -l -d <topology file> <map file>  <command>\n";
	print "-s	Starts a single instance at a later time\n";
	print "-p 	Profiles memory usage\n";
	print "-l 	Username\n";
	print "-d 	Remote working directory\n";

	die;
}
getopts("spl:d:",\%options);
if (defined $options{l}){
	$username=$options{l};
}
if(defined $options{s}){
	$singleFlag=" -s";
}
if(defined $options{p}){
	$profileFlag=" -p";
}
if (defined $options{d}){
	$remotedir=$options{d};
}else{
	$remotedir="/home/ucb_i3/galtekar/dcentdns";
}

my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];
my $command=$ARGV[2];
#print "Command:$command\n";
my %map=();
my %hostmap=();

init_map($mapFile,\%map,\%hostmap);
my $nodes= scalar (keys %hostmap);

my $count=0;
foreach my $key (keys %hostmap){	
	$count++;
	my $value=$map{$key};
	my $host=$hostmap{$key};
	my $dirname="exp.".$value;	
	if ($count == $nodes-1 && $singleFlag ==1){
		sleep(20);
	}
	my $dirname="exp.".$value;	
	print("ssh $username\@$host \" cd $remotedir/$dirname;$command \" &\n");
	system("ssh $username\@$host \" cd $remotedir/$dirname;$command \" &");

	if ($profileFlag){
		my $profileCommand="nohup \./scripts/dns/profile_mem.pl &";
		print("ssh $username\@$host \" cd $remotedir/$dirname;$profileCommand \" &\n");
		system("ssh $username\@$host \" cd $remotedir/$dirname;$profileCommand \" &");
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
