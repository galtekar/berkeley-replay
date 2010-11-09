#! /usr/bin/perl

use strict;
if(@ARGV<1){
	print "$0 <topology file> <map file>\n";
	die;
}
my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];
my $doDebug="false";
my %map=();
my $topdir=`pwd`;
chomp($topdir);
print "top dir:".$topdir."\n";

init_map($mapFile,\%map);
open(FILE,$topologyFile);
my @lines=<FILE>;
my $dir="";
my $neighborFlag=0;
my $configText="";
my $node="";
my $neighborText="";
my $debugText="";
my $flag=0;
my $address;
foreach my $line (@lines){
	if($line=~/^#/){
		next;
	}	
	if($line=~/^id/ ){
		if($flag>0){
			print "Launching $node\n";
			print "mkdir $dir\n";
			if( -d $dir){
				system("rm -rf $dir");
			}
			system("mkdir $dir");
			open(FILE,">".$dir."/config.txt");
			print FILE $configText;
			close(FILE);
			open(FILE,">".$dir."/neighbor.txt");
			print FILE $neighborText;
			close(FILE);
			open(FILE,">".$dir."/debug.txt");
			print FILE $debugText;
			close(FILE);
			print "cp tk $dir\n";
			system("cp tk $dir");
			print("cd $dir;/home/galtekar/src/work/logreplay/remote_package/liblog ./tk config.txt &\n");
			system("cd $dir;/home/galtekar/src/work/logreplay/remote_package/liblog ./tk config.txt &");
		}
		my ($key,$idValue)=split(/=/,$line);
		chomp($idValue);
		my $value=$map{$idValue};
		$configText="";
		$neighborText="";
		$neighborFlag=0;
		$debugText="file $dir/tk\nrun $dir/config.txt";
		$address=$value;
		$node=$value;
		$dir=$topdir."/"."exp.".$value;
		if($flag==0){
			$flag++;
		}
	}
	if($neighborFlag==0 && $line!~/^neighbors/ ){
		if($line=~/^neighbor_file/){
			my @tmpArray=split(/=/,$line);
			$configText=$configText.$tmpArray[0]."=".$dir."/".$tmpArray[1];
		}elsif($line=~/^id/){
			$configText=$configText."address=".$address."\n";
		}
		else{
			$configText=$configText.$line;
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

print "\n";
print "Launching $node\n";
print "mkdir $dir\n";
if( -d $dir){
	system("rm -rf $dir");
}
system("mkdir $dir");
open(FILE,">".$dir."/config.txt");
print FILE $configText;
close(FILE);
open(FILE,">".$dir."/neighbor.txt");
print FILE $neighborText;
close(FILE);
print "cp tk $dir\n";
system("cp tk $dir");
print("cd $dir;/home/galtekar/src/work/logreplay/remote_package/liblog ./tk config.txt &\n");
system("cd $dir;/home/galtekar/src/work/logreplay/remote_package/liblog ./tk config.txt &");


sub init_map(){
	my $mapFile=$_[0];
	my %map;
	open(FILE,$mapFile) or die "Cannot open $mapFile\n";
	my @lines=<FILE>;
	foreach my $line (@lines){
		my ($key,$value)=split(/=/,$line);
		chomp($value);
		my $newValue=$key."_".$value;
		$map{$key}=$newValue;
	}

	%{$_[1]}=%map;
}
