#! /usr/bin/perl
#
use strict;
use Getopt::Std;

if (@ARGV < 1){
	die "Usage:$0 -n <number of nodes>|-f <list of nodes> \n";
}

my %options = ();
getopts ("n:f:", \%options);

if (defined $options{f} && defined $options{n}){
	die "Only one of the two options -n,-f can be specified\n";
}
my $port = 3000;
if (defined $options{n}){
	my $prefix=0;
	my $n = $options{n};
	my @prefix=("s","c","c");
	my @min=(1,67,1);
	my @max=(62,96,10);
	my $index=0;
	my $count=$min[0];
	
	for(my $i=0;$i<$n;$i++,$count++){
		if ( $count>$max[$index]){
			if($prefix){
				$index++;
			}else{
				$port++;
			}
			$count=$min[$index];
		}
		print 	"$i=$prefix[$index]".$count."-$port\n";
	}
} else {
	my $file = $options{f};
	open (FILE , $file);

	while ( <FILE> ){
		chomp;
		print (($.-1));
		print "=$_-$port\n";
	}
	close FILE;
}
