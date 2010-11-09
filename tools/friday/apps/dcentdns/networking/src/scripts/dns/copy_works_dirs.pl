#! /usr/bin/perl

#Starts up servers on a set of  millennium machines
use strict;
use Getopt::Std;
my %options;
my $remotedir;
my $topdir=`pwd`;
chomp($topdir);
my $scriptdir = "scripts/dns";
my $username="sriram_s";

my $singleFlag="";
my $profileFlag="";
my $sharedNFS=1;

if(@ARGV<2){
	print "$0 -s -p -c -l <topology file> <map file>\n";
	print "Copies a set of work directories to the nodes\n";
	print "-l 	Username\n";
	print "-d 	Remote working directory\n";
	die;
}

getopts("l:d:",\%options);

if (defined $options{d}){
	$remotedir=$options{d};
}else{
	$remotedir="/work/sriram_s/dev/networking/src";
}
if (defined $options{l}){
	$username=$options{l};
}else{
	$username="sriram_s";
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
print("$topdir/$scriptdir/make_local_files.pl $topologyFile $mapFile\n");
system("$topdir/$scriptdir/make_local_files.pl $topologyFile $mapFile");

copy_work_dirs();

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
		my $cmd="if [[ ! -d $remotedir ]];then mkdir -p $remotedir;fi";
		print("ssh $username\@$host \" $cmd \" &\n");
		system("ssh $username\@$host \" $cmd \" &");
		
		print("rsync -avz -e ssh $dirname $username\@$host:$remotedir\n");
		system("rsync -avz -e ssh $dirname $username\@$host:$remotedir");
	}
}
