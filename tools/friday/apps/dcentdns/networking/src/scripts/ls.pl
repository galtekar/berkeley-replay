#! /usr/bin/perl -w
#
use strict;
my %edge;
my $verbose=0;
my %neighborMap;
my $node=$ARGV[0];
my $file=$ARGV[1];
my $begin;
my $end;
open(FILE,$file);
my @lines=<FILE>;
my $flag1=1;
foreach my $line (@lines){
	if($flag1==1 && $line=~/event of type:5/){
		$begin=gettime($line);
		$flag1=0;
	}
	if ($line=~/Added routing table entry to \((.*),(.*)\)/){
		if (!defined $neighborMap{$2}){
			@{$neighborMap{$2}}=();
		}
		if($verbose){
			print "Edge $2->$1\n";
		}
		push(@{$neighborMap{$2}},$1);
		my $x=compute($node);
		print $x."\n";
		if ($x==50){
			$end=gettime($line);
			if ($verbose){
				print $line."\n";
			}
			last;
		}
		if($verbose){
			my @tmp=@{$neighborMap{$2}};
			print $2."\t".join(",",@tmp)."\n";
		}
	}
}

if (defined $end){
	if (!defined $begin){
		$begin=$end;
	}
	print $end-$begin."\n";
}

sub compute{
	my $start=$_[0];
	my %distance=();
	my @over=();
	my @list=();
	push(@list, $start);
	$distance{$start}=0;
	my $count=0;
	my %tmpmap;
	while(@list!=0){
		if($verbose){
			print "$count:".join(",",@list)."\n";
		}
		$count++;
		my $min=100;
		my $minIndex;
		for(my $l=0; $l <@list; $l++){
			my $element=$list[$l];
			if (defined $distance{$element} && $distance{$element}<$min){
				$min=$distance{$element};
				$minIndex=$l;
			}
		}
		my $selected=$list[$minIndex];
		$tmpmap{$selected}++;
		push(@over, $selected);
		my @tmp=();
		for (my $k=0;$k<@list;$k++){
			if ($k==$minIndex){
				next;
			}
			push(@tmp, $list[$k]);
		}
		@list=@tmp;
		if($verbose){
			print "selected=$selected\n";
			print "List=".join(",",@list)."\n";
		}
		if (!defined $neighborMap{$selected}){
			return @over;
		}
		my @neighbors=@{$neighborMap{$selected}};
		foreach my $neighbor (@neighbors){
			if ( defined $distance{$neighbor} && $distance{$neighbor}>$distance{$selected}+1){
				$distance{$neighbor}=$distance{$selected}+1;
			}elsif (!defined $distance{$neighbor}){
				$distance{$neighbor}=$distance{$selected}+1;
				push(@list, $neighbor);
			}
		}
		
	}

	return scalar(@over);
}


sub gettime{
	my $line=shift(@_);
	my $time=0;
	if ($line=~ /.([^:]*):([^:]*):([^:]*)\s([^]]*)/){
	#	print $1."\t".$2."\t".$3."\n";
		$time=3600*$1+60*$2+$3+$4/1000000;	
	}
	return $time;
}
