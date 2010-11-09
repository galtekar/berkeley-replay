#!/usr/bin/perl -w

use strict 'vars';
package main;

my $minor_num;

# check if /dev/net/tun exists, if not create it appropriately
my $tun_dev_name = "/dev/net/tun";
if (-e $tun_dev_name) {
    print "$tun_dev_name exists ";
    
    my($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size,
        $atime, $mtime, $ctime, $blksize, $blocks) = 
	stat $tun_dev_name or die "Can't stat $tun_dev_name\n";
    $minor_num = $rdev%256;
} else {
    print "Creating $tun_dev_name ";
    my $cmd = "mknod /dev/net/tun c 10 201";
    system($cmd);
    $minor_num = 201;
}
print "with minor num $minor_num\n";

# Check for a line of the form 'major# tuntab' in /etc/iproute2/rt_tables
my $found_tuntab = 0;
open RTTABLES, "/etc/iproute2/rt_tables";
while (<RTTABLES>) {
    chomp $_;
    if ($_ =~ /^#/) {
	next;
    }
    if ($_ =~ /tuntab/) {
	$found_tuntab = 1;
	print "Found tuntab entry in rt_tables: $_\n";
	last;
    }
}

if (!$found_tuntab) {
    print "Adding tuntab entry to rt_tables\n";
    my $cmd = "echo \'$minor_num tuntab\' >> /etc/iproute2/rt_tables";
    print $cmd."\n";
    system($cmd);
}
