#! /usr/bin/perl

use strict;
use File::Find;
use Getopt::Std;


my $maxsentcount=0;
my $maxreceivedcount=0;
my $maxsentbytes=0;
my $maxreceivedbytes=0;

my $avgsentcount=0;
my $avgreceivedcount=0;
my $avgsentbytes=0;
my $avgreceivedbytes=0;
my @tags=
qw(GENERATE_KEY_START 
GENERATE_KEY_END 
SEND_INIT_PV_START 
SEND_INIT_PV_END 
SEND_INCREMENT_PV_START 
SEND_INCREMENT_PV_END 
RECEIVE_INIT_PV_START 
RECEIVE_INIT_PV_END 
RECEIVE_INCREMENT_PV_START 
RECEIVE_INCREMENT_PV_END 
VERIFY_PV_START 
VERIFY_PV_END 
SEND_FAKE_INIT_PV_START 
SEND_FAKE_INIT_PV_END );
my %map=(
GENERATE_KEY_END => "GENERATE_KEY",
SEND_INIT_PV_END => "SEND_INIT_PV",
SEND_INCREMENT_PV_END => "SEND_INCREMENT_PV" ,
RECEIVE_INIT_PV_END=>"RECEIVE_INIT_PV" ,
RECEIVE_INCREMENT_PV_END=>"RECEIVE_INCREMENT" ,
VERIFY_PV_END =>"VERIFY_PV",
SEND_FAKE_INIT_PV_END =>"SEND_FAKE_INIT_PV");

my $start;
my $end;
my %times1=();
my %sqtimes1=();
my %counts1=();
my %times2=();
my %sqtimes2=();
my %counts2=();
my $verbose=0;
my $werbose=0;
my $xerbose=0;
my %options;
my $total=0;
getopts("vwxa",\%options);

if(@ARGV<1){
	die "Usage:$0 directory\n";
}

if (defined $options{v}){
	$verbose=1;
}
if (defined $options{w}){
	$werbose=1;
}
if (defined $options{x}){
	$xerbose=1;
}

my $directory=$ARGV[0];

find(\&Compute,$directory);
if (($xerbose==0)&& ($verbose==1 || $werbose==1|| defined $options{a})){
foreach my $key (keys %times1){
	my $n=$counts1{$key};
	my $dev=$sqtimes1{$key}/$n-($times1{$key}/$n)**2;
#	print $key."\t".$n."\t".$times1{$key}/$counts1{$key}."\t".(1.96*sqrt($dev)/sqrt($n))."\n";
	printf("%s\t%d\t%10.2f\t%10.2f\n",$key,$n,$times1{$key}/$counts1{$key},(1.96*sqrt($dev)/sqrt($n)));
}
}
if ($xerbose==0 && $werbose==0){
foreach my $key (keys %times2){
	my $n=$counts2{$key};
	my $dev=$sqtimes2{$key}/$n-($times2{$key}/$n)**2;
#	print $key."\t".$n."\t".$times2{$key}/$counts2{$key}."\t".sqrt($dev)."\n";
	printf("%s\t%d\t%10.2f\t%10.2f\n",$key,$n,$times2{$key}/$counts2{$key},(1.96*sqrt($dev)/sqrt($n)));
}
}
if ($xerbose==1){
	message_count();
	print $total."\t".$avgsentcount/$total."\t".$avgreceivedcount/$total."\t".$avgsentbytes/$total."\t".$avgreceivedbytes/$total."\t".$maxsentcount."\t".$maxreceivedcount."\t".$maxsentbytes."\t".$maxreceivedbytes."\n";
}
sub Compute{
	my $file=$_;
	my $set=0;
	my $flag=0;
	if (!(defined $options{a}) && $file !~/log.*\..*\..*\..*\./ ){
		return;
	}
	$total++;
	if ($verbose == 1){
		print $file ."\n";
	}
	open(FILE,$file);
	my @lines=<FILE>;
	foreach my $line (@lines){
	chomp($line);
	if($line=~/Killed/){
		$flag=1;
	}

	if($flag==1){
		if($set==0){
			for(my $i=0;$i<@tags;$i++){
				if(rindex($line,$tags[$i])!=-1){
				$set=1;	
				my @tmp=split(/:|\s+/,$line);
				$start=$tmp[4];
				}
			}
		}else{
			$set=0;
			my @tmp=split(/:|\s+/,$line);
			$end=$tmp[4];
			my $key=$tmp[$#tmp];
			my $seq=$tmp[$#tmp-2];
			my $time=$end-$start;
			my $tmpKey=$map{$key};
			if($tmpKey =~ /GENERATE/){
#				print $tmpKey."\t".$time."\n";
			}
			$times1{$tmpKey.":".$seq}+=$time;
			$sqtimes1{$tmpKey.":".$seq}+=$time*$time;
			$counts1{$tmpKey.":".$seq}++;
			$times2{$tmpKey}+=$time;
			$sqtimes2{$tmpKey}+=$time*$time;
			$counts2{$tmpKey}++;
		}
	}
	}
	if ($xerbose==0 && $verbose ==1 ){
		foreach my $tmpKey (keys %times2){
			print $tmpKey."\t".$times2{$tmpKey}/$counts2{$tmpKey}."\n";	
		}
	}
}



sub get_size{
	my $length=$_[0];
	my $size=($length+1)*180+($length)*168+68;
	return $size;
}

sub message_count{
	my $sentcount=0;
	my $receivedcount=0;
	my $sentbytes=0;
	my $receivedbytes=0;
	foreach my $tmpKey (keys %times1){
		my ($key, $hops)=split(/:/,$tmpKey);
		if($tmpKey =~ /SEND/){
			$sentcount+=$counts1{$tmpKey};
			$sentbytes+=$counts1{$tmpKey}*get_size($hops);
		}
		if($tmpKey =~ /RECEIVE/){
			$receivedcount+=$counts1{$tmpKey};
			$receivedbytes+=$counts1{$tmpKey}*get_size($hops);
		}
	}
	if ($xerbose ==1){
	$avgsentcount+=$sentcount;
	$avgreceivedcount+=$receivedcount;
	$avgsentbytes+=$sentbytes;
	$avgreceivedbytes+= $receivedbytes;
	if ($sentcount > $maxsentcount){
		$maxsentcount=$sentcount;
	}
	if($receivedcount>$maxreceivedcount){
		$maxreceivedcount=$receivedcount;
	}
	if($sentbytes > $maxsentbytes){
		$maxsentbytes=$sentbytes;
	}
	if($receivedbytes > $maxreceivedbytes){
		$maxreceivedbytes = $receivedbytes;
	}
	}
}
