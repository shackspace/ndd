#! /usr/bin/perl
# ndd
# network device discovery
# (c) 2011 hadez@nrrd.de
#
# this script dumps the ARP table of a cisco switch and uses the publicly available oui.txt[1] to check what device a given MAC belongs to.
#
# [1] http://standards.ieee.org/develop/regauth/oui/oui.txt
#

use strict;
my @cmd_nmap = qw(snmpwalk -v2c -c <community> 10.42.0.1 1.3.6.1.2.1.3.1.1.2);
my $OUISRC = "http://standards.ieee.org/develop/regauth/oui/oui.txt";
my %Devices = ();
my %oui = ();

if(!-e "oui.txt")
{
	system("wget $OUISRC");
}

open NMAP,"-|",@cmd_nmap or die "cannot run '@cmd_nmap':$!";
while(<NMAP>){
	chomp;
	if(/(\d+\.\d+\.\d+\.\d+) = Hex-STRING:((\s[0-9A-Z]{2}){6})/){
		my $hstring = $2;
		$hstring =~ s/\s//g;
		$Devices{$hstring}++;
	}
}
close NMAP;

open(OUI,"oui.txt") or die "cannot open oui.txt: $!";
while(<OUI>){
    chomp;
    if(/^([0-9A-Z-]+)\s+\(hex\)\s+(.*)/){
        my $venid = $1;
        my $venname = $2;
        $venid =~ s/-//g;
        $oui{$venid}=$venname;
    }    
}
close OUI;

foreach(keys %Devices){
    my ($venid) = ($_ =~ /^(.{6})/);
    print "$_ $Devices{$_} $oui{$venid}\n";
}

