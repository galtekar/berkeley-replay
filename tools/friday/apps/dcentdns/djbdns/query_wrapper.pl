#! /usr/bin/perl -w
#
#
# Wrapper around dnsquerygenerator.
# Queries multiple servers selected at random.
#


use Time::gmtime;

if (@ARGV < 3){
	print "Usage: $0 <Number of servers> <Redundancy> <Trace file>\n";
	die;
}

my $servers	= shift @ARGV;
my $k		= shift @ARGV;
my $traceFile = shift @ARGV;
my $seed	= 1;
$|			= 1;

my %ipMap 	= read_association("hosts.txt");
my $port	= 3001;
srand $seed;


open (LOGFILE, ">trace.log");
open (TRACEFILE, "$traceFile");
while (<TRACEFILE>){
	my $gm = gmtime();
	print LOGFILE "#################\n";
	print LOGFILE "[".$gm->hour().":".$gm->min().":".$gm->sec()."]:";
	print LOGFILE "Query number:$.\n";
	chomp ;
	my $url = $_;
	my @pool = (1..$servers);
	my @selection = ();
	while (@selection < $k){
		my $selected = rand (@pool);		
		push (@selection, $pool[$selected]);
		splice ( @pool, $selected, 1);
	}

	foreach my $server (@selection){
		my $cmd = "echo $url|./dnstracegenerator 1 1|./dnsquerygenerator -p $port -s $ipMap{$server}";
		my $result 	= `$cmd`;
		$result		= "**************\nQueried s$server\n".$result."\n";
		print $result;
		print LOGFILE $result;
	}

}
close LOGFILE;



# Get the association of names to IPs
#
sub read_association {
	my $file  	= shift @_;
	my %map 	= ();
	open (FILE, $file) or die "$0: Cannot find $file\n";
	while (<FILE>){
		chomp;
		my ($key, $value) = split (/\s+/);
		$map{$key} = $value;
	}

	return %map;
	close FILE;
}
