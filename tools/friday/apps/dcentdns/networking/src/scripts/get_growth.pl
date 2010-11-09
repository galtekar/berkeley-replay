#! /usr/bin/perl -w
#
use strict;
use Getopt::Std;
my %options;
my $begin;
my $end;

if (@ARGV<2){
	print "Usage:$0 <nodes> <file\n";
	die;
}

getopts("f",\%options);
my $flag=1;

if (defined $options{f}){
	$flag=0;
}
my $maxnodes=$ARGV[0];
my $file=$ARGV[1];
my $count=0;
my $nodes;
open(FILE,$file);
my @lines=<FILE>;
foreach my $line (@lines){
	my $time;
	chomp($line);
	if($count==0){
		$begin=gettime($line);
	}
	if($line=~/verified non-malicious nodes:(.*)/){
		my $tmp=$1;
		chomp($tmp);
		$nodes=$tmp;
		$time=gettime($line)-$begin;
		if ($flag){
			print $time."\t".$nodes."\n";
		}
		if ($nodes>=$maxnodes){
			last;
		}
	}
	if($flag==0 && $line=~/unverified nodes:(.*)/){
		my $tmp=$1;
		chomp($tmp);
		$nodes+=$tmp;
		$time=gettime($line)-$begin;
		print $time."\t".$nodes."\n";
		if ($nodes>=$maxnodes){
			last;
		}
	}	
	$count++;
}

sub gettime{
	my $line=shift(@_);
	my $time=0;
	if ($line=~ /.([^:]*):([^:]*):([^:]*)\s([^]]*)/){
#		print $1."\t".$2."\t".$3."\t".$4."\n";
		$time=3600*$1+60*$2+$3+$4/1000000;	
#		$time=3600*$1+60*$2+$3;	
#		print "time=".$time."\n";
	}
	return $time;
}
