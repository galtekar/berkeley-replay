#! /usr/bin/perl
#
use strict;
use Getopt::Std;

if (@ARGV < 1){
	die "Usage:$0 <nodes> \n";
}

my $useFile=0;
my $file="";
my $port = 3000;
my %options;
getopts("f:p:",\%options);

if(defined $options{p}){
	$port=$options{p};
}
my $n=$ARGV[0];
my @hosts = get_hosts ($n, \%options);

for(my $i=0;$i<$n;$i++){
	chomp($hosts[$i]);
	print "$i=$hosts[$i]-$port\n";
}


sub get_hosts{
	my $n=$_[0];
	my %options=%{$_[1]};
	if (defined $options{f}){
		my $file = $options{f};
		open (FILE, $file);
		my @hosts=<FILE>;
		@hosts=@hosts[0..$n-1];
		return @hosts;
	}else{
		my @hosts=();
		#Machine names on the millennium cluster
		my @prefix=("s","c","c");
		#Maximum maxhines on each set of machines
		my @min=(1,67,1);
		my @max=(62,96,10);
		my $count=$min[0];
		my $index=0;
		for (my $i=0; $i<$n; $i++, $count++){
			if ( $count>$max[$index] && $index<$#prefix){
				$index++;
				$count=$min[$index];
			}
			push (@hosts, "$prefix[$index]$count");
		}
		return @hosts;	
	}
}
