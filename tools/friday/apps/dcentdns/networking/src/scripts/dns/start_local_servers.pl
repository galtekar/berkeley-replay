#! /usr/bin/perl

use strict;
if(@ARGV<1){
	print "$0 <topology file> <map file>\n";
	die;
}
my $dnsDir="../../djbdns";
my $topologyFile=$ARGV[0];
my $mapFile=$ARGV[1];
my $doDebug="false";
my %map=();
my $topdir=`pwd`;
chomp($topdir);
print "top dir:".$topdir."\n";

# Use the map file to map the ids to IP, Port names
init_map($mapFile,\%map);
 
# The file contains the global topology of server nodes 
open(FILE,$topologyFile);

{
local $/="#\n";
my $c=0;
while (<FILE>){

	my $configText="";
	my $dnsConfigText="";
	my $node="";
	my $neighborText="";
	my $debugText="";
	my $neighborFlag=0;
	my $address;
	my $port;
	my $dir="";
	
	my @lines= split (/\n/);
	foreach my $line (@lines){
		if ($line=~/^id/){
			print $line."\n";
			my ($key,$idValue)=split(/=/,$line);
			chomp($idValue);
			my $value=$map{$idValue};
			$debugText="file $dir/tk\nrun $dir/config.txt";
			$address=$value;
			my @tmp=split (/-/, $address);
			$port=@tmp[2];
			$node=$value;
			$dir="exp.".$value;
			chomp($dir)

		}
		if($neighborFlag==0 && $line!~/^neighbors/ ){
			if($line=~/^neighbor_file/){
				my @tmpArray=split(/=/,$line);
				$configText=$configText.$tmpArray[0]."=".$tmpArray[1]."\n";
			}elsif($line=~/^id/){
				$configText=$configText."address=".$address."\n";
				$configText=$configText."dns_port=".($port+2)."\n";
				$dnsConfigText=$dnsConfigText."port=".($port+1)."\n";
			}
			else{
				$configText=$configText.$line."\n";
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

	print "Launching $node\n";
	print "mkdir $dir\n";
	if( -d $dir){
		system("rm -rf $dir");
	}
	system("mkdir $dir");
	open  (FILE1,">".$dir."/config.txt");
	print FILE1 $configText;
	close FILE1;
	open  (FILE1,">".$dir."/neighbor.txt");
	print FILE1 $neighborText;
	close FILE1;
	open  (FILE1,">".$dir."/debug.txt");
	print FILE1 $debugText;
	close FILE1;
	open  (FILE1, ">".$dir."/dns_config.txt");
	print FILE1 $dnsConfigText;
	close FILE1;
	print  	"cp tk $dir\n";
	system 	"cp tk $dir";
	print	"cd $dir;./tk config.txt &\n";
	system	"cd $dir;./tk config.txt &";
	print 	"cp $dnsDir/codonssecureserver $dir\n";
	system 	"cp $dnsDir/codonssecureserver $dir";
	print 	"cp $dnsDir/dns_launcher.pl $dir\n";
	system 	"cp $dnsDir/dns_launcher.pl $dir\n";
	print 	"cp -r $dnsDir/servers $dir\n";
	system 	"cp -r $dnsDir/servers $dir\n";
	print	"cd $dir;./dns_launcher.pl dns_config.txt&\n";
	system	"cd $dir;./dns_launcher.pl dns_config.txt&\n";
}

}

sub init_map(){
	my $mapFile=$_[0];
	my %map;
	open(FILE,$mapFile) or die "Cannot open $mapFile\n";
	my @lines=<FILE>;
	foreach my $line (@lines){
		my ($key,$value)=split(/=/,$line);
		chomp($value);
		my $newValue=$key."-".$value;
		$map{$key}=$newValue;
	}

	%{$_[1]}=%map;
}
