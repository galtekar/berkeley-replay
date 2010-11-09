#!/usr/bin/perl
#This script tries to ssh to a specified list of PlanetLab nodes.  It produces the following two files:
# a. plab_testssh.success.txt  - list of nodes to which ssh was successful
# b. plab_testssh.fail.txt     - list of nodes to which ssh failed.

use strict;

my $successFile = "plab_testssh.success.txt";
my $failFile = "plab_testssh.fail.txt";
my $userName = "ucb_i3";

# Read in command line arguments
my $numArgs = $#ARGV + 1;
if ($numArgs < 1) {
    
    die "Usage: ./plab_testssh.pl <hostlist>.\n";
}


my $hostFile = $ARGV[0];
print "Using host file : $hostFile.\n";

open SUCCFD, ">$successFile" || die "Unable to open $successFile for writing ...\n";
open FAILFD, ">$failFile" || die "Unable to open $failFile for writing ...\n";

# Go through each line of the host file
open HOSTFD, "$hostFile" || die "Unable to open $hostFile.\n";

while (<HOSTFD>) {

    my $currLine = $_;
    
    if ( $currLine =~ /^\#/) {
        # comment, ignore
        next;
    }
        
    chomp ($currLine);
    print "Trying to ssh to $currLine ...";

    `ssh -q -o "ConnectTimeout=20" -o "StrictHostKeyChecking no" $userName\@$currLine "ls"`;
    print " $? ";
    if ( $? != 0) {
        print "FAIL\n";
        print FAILFD "$currLine\n";
    } else {
        print "SUCCESS\n";
        print SUCCFD "$currLine\n";
    }
    
}
close SUCCFD;
close FAILFD;
close HOSTFD;

