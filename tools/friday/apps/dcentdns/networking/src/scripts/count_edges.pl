#! /usr/bin/perl -w
#
use strict;
my $count=0;
my $flag=0;
while (<>){
	if (/neighbors/){
		$flag=1;
	}
	elsif (/^#/){
		$flag=0;
	}else{
		if ($flag){
			$count++;
		}
	}	
}
$count/=2;
print $count."\n";
