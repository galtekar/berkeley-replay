#! /usr/bin/perl

use strict;

my $configFile=$ARGV[0];
open (FILE, $configFile) or die "Cannot open $configFile\n";
my %map=();

while (<FILE>){
	chomp;
	my ($key, $value)= split (/=/);
	$map{$key}=$value;	
}

#my $cmd = "/home/ucb_i3/galtekar/remote_package/liblog ./codonssecureserver -o -p ".$map{"port"};
my $cmd = "./codonssecureserver -o -p ".$map{"port"};
print $cmd."\n";
system $cmd;

