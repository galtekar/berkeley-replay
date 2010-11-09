#! /usr/bin/perl -w

use strict;
use Getopt::Std;
my %options;

getopts("c", \%options);

if(@ARGV<4){
	die "Usage:$0 n k malicious seed \n";
}

my $n=$ARGV[0];
my $k=$ARGV[1];
my $seed=$ARGV[3];
my $malicious=$ARGV[2];
my $verbose=0;

#my $p=(log($n)+$k*log(log ($n)))(log(2)*$n);
my @matrix=();
for(my $i=0;$i<$n;$i++){
	for(my $j=0;$j<$n;$j++){
		$matrix[$i][$j]=0;
	}
}

srand $seed;

for(my $i=0;$i<$n;$i++){
	for(my $j=1;$j<=$k;$j++){
		#print "Choice=".$choice."\t";
		my $flag=1;
		while ($flag){
			my $choice=int rand $n;
			if ($choice==$i || $matrix[$i][$choice]==1){
				$flag=1;
			}else{
				$matrix[$i][$choice]=1;
				$flag=0;
			}
		}
#	print "\n";
	}
}

for(my $i=0;$i<$n;$i++){
	for(my $j=0;$j<$n;$j++){
		$matrix[$i][$j]=$matrix[$j][$i] if $matrix[$j][$i];
		$matrix[$j][$i]=$matrix[$i][$j] if $matrix[$i][$j];
		#print $matrix[$i][$j]."\t";
	}
	#print "\n";
}

for(my $i=0;$i<$n;$i++){
	my $degree=0;
	print "id=$i\n";
	if($i<$malicious){
	print <<OUT;
is_malicious=true
neighbor_file=neighbor.txt
level=silent
scheduler=priority
n=$n
neighbors
mal_frequency=1
OUT

	}else{
	print <<OUT;
is_malicious=false
neighbor_file=neighbor.txt
level=silent
scheduler=priority
router_type=none
optimization=0
no_crypto=false
n=$n
mal_frequency=1
neighbors
OUT
	}
	for(my $j=0;$j<$n;$j++){
		if($matrix[$i][$j]){
			$degree++;
			print $j."\n";
		}
	}
	if ($verbose){
		print "degree=$degree\n";
	}
	if($i !=$n-1){
		print "#\n";
	}
}
