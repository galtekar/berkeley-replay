#! /usr/bin/perl -w
#
use strict;
use Getopt::Std;
my %options;
my $begin;
my $end;

getopts("mfh",\%options);
my $flag=0;
my $mal=" non-malicious";
if (defined $options{f}){
	$flag=1;
}
if (defined $options{m}){
	$mal="";
}

if (@ARGV<2){
	print "Usage:$0 <nodes> <file>\n";
	print "Gets the discovery time\n";
	die;
}
my $nodes=$ARGV[0];
my $file=$ARGV[1];
my $l1;
my $l2;
my $sign=0;
my $count=0;
my $flag1=1;
open(FILE,$file);
my @lines=<FILE>;
foreach my $line (@lines){
	chomp($line);
	if($flag1==1 && $line=~/Number of verified/){
		$begin=gettime($line);
		$flag1=0;
	}
	if($line=~/verified$mal nodes:(.*)/){
		my $tmp=$1;
		chomp($tmp);
		$l1=$tmp;
		if (!$flag && $l1>= $nodes){
			$end=gettime($line);
			$sign=1;
			last;
		}
	}
	if($flag && $line=~/unverified nodes:(.*)/){
		my $tmp=$1;
		chomp($tmp);
		$l2=$tmp;
		if ($l1+$l2>= $nodes){
			$end=gettime($line);
			$sign=1;
			last;
		}
	}
	
	$count++;
}
#print $begin."\t".$end."\n";
if ($sign){
	print $end-$begin."\n";
}

sub gettime{
	my $line=shift(@_);
	my $time=0;
	if ($line=~ /.([^:]*):([^:]*):([^:]*)\s([^]]*)/){
	#	print $1."\t".$2."\t".$3."\n";
		if (defined $options{h}){
			$time=3600*$1+60*$2+$3+$4/1000000;	
		}else{
			$time=3600*$1+60*$2+$3;	
		}
	}
	return $time;
}
