#! /usr/bin/perl

#Starts up servers on a set of  millennium machines
use strict;
use Getopt::Std;
my %options;
my $remotedir;
my $topdir=`pwd`;
chomp($topdir);
my $scriptdir = "scripts/dns";
my $username="ucb_i3";

my $singleFlag="";
my $profileFlag="";
my $sharedNFS = 1;
my $execute = 0;

if(@ARGV<2){
	print "$0 -s -p -c -l <topology file> <map file>\n";
	print "Starts up a set of servers on the millennium cluster\n";
	print "-s	Starts a single instance at a later time\n";
	print "-x 	Execute the instance\n";
	print "-p 	Profiles memory usage\n";
	print "-c	Copy files onto remote machines\n";
	print "-l 	Username\n";
	print "-d 	Remote working directory\n";
	die;
}

getopts("spcl:d:x",\%options);
if(defined $options{s}){
	$singleFlag=" -s";
}
if(defined $options{p}){
	$profileFlag=" -p";
}
if (defined $options{c}){
	$sharedNFS=0;
}
if (defined $options{d}){
	$remotedir=$options{d};
}else{
	$remotedir="/home/ucb_i3/galtekar/dcentdns";
}
if (defined $options{l}){
	$username=$options{l};
}else{
	$username="ucb_i3";
}
if (defined $options{x}){
	$execute = 1;
}


my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];

#Maps server ids to a host string
my %map=();

#Maps servers ids to a host name/host IP
my %hostmap=();



#Initialize the maps
init_map($mapFile,\%map,\%hostmap);


#Make the directories that represent each server locally.
system("$topdir/$scriptdir/make_local_files.pl $topologyFile $mapFile");

if (! $sharedNFS){
	copy_work_dirs();
}

if ($execute){
	# Launch the servers on the specified nodes
	#
	# For millennium servers we do't need to do remote copies.
	my $cmd="nohup ./launcher";


	system("$topdir/$scriptdir/exec.pl $singleFlag $profileFlag -d $remotedir -l $username $topologyFile $mapFile \"$cmd\"\n");
}


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

# Copies the work directories onto remote machines
# Not needed on a shared NFS
sub copy_work_dirs{
	foreach my $key (keys %hostmap){
		my $value=$map{$key};
		my $host=$hostmap{$key};
		my $dirname="exp.".$value;	
		my $cmd="if [[ ! -d $remotedir ]];then mkdir -p $remotedir;else rm -rf $remotedir;fi";
		system("ssh $username\@$host \" $cmd \" ");
		
		system("rsync -avz -e ssh $dirname $username\@$host:$remotedir");
	}
}
