#! /usr/bin/perl -w

use strict;
if(@ARGV<1){
	die "Usage:$0 n\n";
}

my $n=$ARGV[0];
for(my $i=0;$i<$n;$i++){
	print "id=$i\n";
	print <<OUT;
is_malicious=false
neighbor_file=neighbor.txt
level=normal
neighbors
OUT
	if($i!=0){
		my $j=$i-1;
		print $j."\n";
	}
	if($i !=$n-1){
		my $j=$i+1;
		print $j."\n";
		print "#\n";
	}
}
