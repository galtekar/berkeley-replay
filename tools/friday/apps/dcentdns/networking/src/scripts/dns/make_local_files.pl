#! /usr/bin/perl

# Makes config files for the topology and the map file and stores all of them in `pwd`
use strict;
if(@ARGV<2){
	print "$0 <topology file> <map file>\n";
	die;
}
my $dnsdir="../../djbdns";
my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];
my %map=();
my @malList=();
my $topdir=`pwd`;
chomp($topdir);
#print "top dir:".$topdir."\n";

init_map($mapFile,\%map);
init_mal_map($topologyFile, \@malList);


{
# The file contains the global topology of server nodes 
open(FILE,$topologyFile);
local $/="#\n";
my $c=0;
while (<FILE>){

	my $configText="";
	my $dnsConfigText="";
	my $node="";
	my $neighborText="";
	my $debugText="";
	my $neighborFlag=0;
	my $address;
	my $port;
	my $dir="";
	
	my @lines= split (/\n/);
	foreach my $line (@lines){
		if ($line=~/^id/){
			print $line."\n";
			my ($key,$idValue)=split(/=/,$line);
			chomp($idValue);
			my $value=$map{$idValue};
			$debugText="file $dir/tk\nrun $dir/config.txt";
			$address=$value;
			my @tmp=split (/-/, $address);
			$port=@tmp[2];
			$node=$value;
			$dir="exp.".$value;
			chomp ($dir);
		}
		if($neighborFlag==0 && $line!~/^neighbors/ ){
			if($line=~/^neighbor_file/){
				my @tmpArray=split(/=/,$line);
				$configText=$configText.$tmpArray[0]."=".$tmpArray[1]."\n";
			}elsif($line=~/^id/){
				$configText=$configText."address=".$address."\n";
				$configText=$configText."dns_port=".($port+2)."\n";
				$dnsConfigText=$dnsConfigText."port=".($port+1)."\n";
			}
			else{
				$configText=$configText.$line."\n";
			}	
		}
		if($neighborFlag==1){
			my $key=$line;
			chomp($key);
			$neighborText=$neighborText.$map{$key}."\n";
		}
		if($line=~/^neighbors/){
			$neighborFlag=1;
		}
	}

	print "************************\n";
	print "Launching $node\n";
	if( -e $dir){
		print ("rm -rf $dir\n");
		system("rm -rf $dir");
	}
	print "mkdir $dir\n";
	system("mkdir $dir");

	print 	"cp -r scripts $dir/scripts\n";
	system 	"cp -r scripts $dir/scripts\n";
	print 	"cp launcher  $dir\n";
	system  "cp launcher  $dir\n";
	
	open  (FILE1,">".$dir."/config.txt");
	print FILE1 $configText;
	close FILE1;
	open  (FILE1,">".$dir."/neighbor.txt");
	print FILE1 $neighborText;
	close FILE1;
	open  (FILE1,">".$dir."/debug.txt");
	print FILE1 $debugText;
	close FILE1;
	open  (FILE1, ">".$dir."/dns_config.txt");
	print FILE1 $dnsConfigText;
	close FILE1;
	print  	"cp tk $dir\n";
	system 	"cp tk $dir";
	print 	"cp $dnsdir/codonssecureserver $dir\n";
	system 	"cp $dnsdir/codonssecureserver $dir";
	print 	"cp $dnsdir/dns_launcher.pl $dir\n";
	system 	"cp $dnsdir/dns_launcher.pl $dir\n";
	print 	"cp -r $dnsdir/servers $dir\n";
	system 	"cp -r $dnsdir/servers $dir\n";
}

}

sub init_map(){
	my $mapFile=$_[0];
	my %map;
	open(FILE,$mapFile) or die "Cannot open $mapFile\n";
	my @lines=<FILE>;
	foreach my $line (@lines){
		my ($key,$value)=split(/=/,$line);
		chomp($value);
		my $newValue=$key."-".$value;
		$newValue=~s/:/-/g;
		$map{$key}=$newValue;
	}

	%{$_[1]}=%map;
}

sub init_mal_map{
	my $mapFile=$_[0];
	my @list;
	open(FILE,$mapFile) or die "Cannot open $mapFile\n";
	my @lines=<FILE>;
	my $key;
	foreach my $line (@lines){
		if($line=~/^#/){
			next;
		}	
		chomp($line);
		if ($line=~/^id/){
			my @tmp=split(/=/,$line);
			$key=$tmp[1];
		}
		if ($line=~/is_malicious/){
			my @tmp=split(/=/,$line);
			if ( $tmp[1] eq "true"){
				unshift(@list,$key);
			}
		}
	}
	@{$_[1]}=@list;
}
