#! /usr/bin/perl

# This perl script generates parts of the test suite.

use strict;
use warnings;

if (! -e "generate.pl") {
    die "You must invoke this script in the testsuite directory.\n";
}

sub checksum ($) {
    my $data = shift;
    my $length = length $data;
    my $sum = 0;

    if ($length % 2) {
	$sum = ord(substr($data, $length - 1, 1));
    }

    for my $short (unpack "S*", $data) {
	$sum += $short;
    }

    while ($sum >> 16) {
	$sum = ($sum & 0xFFFF) + ($sum >> 16);
    }
    return 0xFFFF & ~$sum;
}

sub ip_header_length ($) {
    my $packet = shift;
    return (unpack ("C", $packet) & 0x0F) * 4;
}

sub fix_ip_checksum (\$) {
    my $packet = shift;
    substr $$packet, 10, 2, "\000\000";	# zero checksum
    my $cksum = checksum (substr $$packet, 0, ip_header_length $$packet);
    substr $$packet, 10, 2, pack ("S", $cksum);
}

sub fix_ip_length (\$) {
    my $packet = shift;

    substr $$packet, 2, 2, pack ("n", length $$packet);
    fix_ip_checksum $$packet;
}

sub pseudo_header ($$) {
    my ($packet, $length) = @_;
    return substr ($packet, 12, 8)
	. "\000" . substr ($packet, 9, 1)
	. $length;
}

sub fix_udp_checksum (\$) {
    my $packet = shift;
    my $ip_length = ip_header_length $$packet;
    substr $$packet, $ip_length + 6, 2, "\000\000"; # zero checksum
    my $cksum = checksum (pseudo_header ($$packet, substr ($$packet, $ip_length + 4, 2))
			  . substr ($$packet, $ip_length));
    substr $$packet, $ip_length + 6, 2, pack ("S", $cksum);
}

sub udp_data ($) {
    my $packet = shift;
    return substr $packet, ip_header_length ($packet) + 8;
}

sub fix_udp_length (\$) {
    my $packet = shift;
    my $ip_length = ip_header_length $$packet;
    my $udp_length = length ($$packet) - $ip_length;
    substr $$packet, $ip_length + 4, 2, pack ("n", $udp_length);
    fix_udp_checksum $$packet;
}

sub bin2hex ($) {
    my $data = shift;
    my $result = "";
    for my $c (split //, $data) {
	$result = sprintf "%s%02x", $result, ord $c;
    }
    return $result;
}


die if checksum (join "", map chr, map hex, qw(00 01 f2 03 f4 f5 f6)) != 0x423;
die if checksum (join "", map chr, map hex, qw(00 01 f2 03 f4 f5 f6 f7)) != 0xd22;

my @data = map hex, qw(45 00 01 66 87 6d 40 00 f6 11 78 03 51 5b a1 05
	      d4 09 bd ab 00 35 80 20 01 52 fa 27 ac d9 85 00 00 01 00
	      0b 00 00 00 07 02 64 65 00 00 02 00 01 c0 0c 00 02 00 01
	      00 01 51 80 00 08 01 68 03 6e 69 63 c0 0c c0 0c 00 02 00
	      01 00 01 51 80 00 0a 01 69 02 64 65 03 6e 65 74 00 c0 0c
	      00 02 00 01 00 01 51 80 00 04 01 6a c0 22 c0 0c 00 02 00
	      01 00 01 51 80 00 04 01 6b c0 22 c0 0c 00 02 00 01 00 01
	      51 80 00 04 01 61 c0 22 c0 0c 00 02 00 01 00 01 51 80 00
	      04 01 62 c0 36 c0 0c 00 02 00 01 00 01 51 80 00 04 01 63
	      c0 36 c0 0c 00 02 00 01 00 01 51 80 00 04 01 64 c0 36 c0
	      0c 00 02 00 01 00 01 51 80 00 04 01 65 c0 22 c0 0c 00 02
	      00 01 00 01 51 80 00 04 01 66 c0 22 c0 0c 00 02 00 01 00
	      01 51 80 00 04 01 67 c0 36 c0 20 00 01 00 01 00 01 51 80
	      00 04 c0 24 90 d3 c0 4a 00 01 00 01 00 01 51 80 00 04 42
	      23 d0 2c c0 5a 00 01 00 01 00 01 51 80 00 04 d2 51 0d b3
	      c0 6a 00 01 00 01 00 01 51 80 00 04 51 5b a1 05 c0 aa 00
	      01 00 01 00 01 51 80 00 04 c1 ab ff 22 c0 ba 00 01 00 01
	      00 01 51 80 00 04 c1 00 00 ed c0 6a 00 1c 00 01 00 01 51
	      80 00 10 20 01 06 08 00 06 00 00 00 00 00 00 00 00 00
	      05);

for (my $length = 1; $length < 20; ++$length) {
    my $name = sprintf "default_auto-incomplete-%02d", $length;
    open IN, "> $name.in";
    print IN join ("", map chr, @data[0 .. $length - 1]);
    close IN;

    open OUT, "> $name.expected";
    print OUT "dnslogger-forward: debug: Short packet of length $length.\n";
    print OUT "dnslogger-forward: debug: No data received.\n";
    close OUT;
}

for (my $length = 20; $length < 28; ++$length) {
    my $name = sprintf "default_auto-incomplete-%02d", $length;
    my $data = join ("", map chr, @data[0 .. $length - 1]);
    fix_ip_length $data;

    open IN, "> $name.in";
    print IN $data;
    close IN;

    open OUT, "> $name.expected";
    print OUT "dnslogger-forward: debug: Truncated UDP header (81.91.161.5 -> 212.9.189.171).\n";
    print OUT "dnslogger-forward: debug: No data received.\n";
    close OUT;
}

for (my $length = 28; $length < 40; ++$length) {
    my $name = sprintf "default_auto-incomplete-%02d", $length;
    my $data = join ("", map chr, @data[0 .. $length - 1]);
    fix_ip_length $data;
    fix_udp_length $data;

    open IN, "> $name.in";
    print IN $data;
    close IN;

    open OUT, "> $name.expected";
    printf OUT "dnslogger-forward: debug: Truncated DNS packet (length %d).\n", $length - 28;
    print OUT "dnslogger-forward: debug: No data received.\n";
    close OUT;
}

for (my $length = 40; $length < 100; ++$length) {
    my $name = sprintf "default_auto-complete-%02d", $length;
    my $data = join ("", map chr, @data[0 .. $length - 1]);
    fix_ip_length $data;
    fix_udp_length $data;

    open IN, "> $name.in";
    print IN $data;
    close IN;

    open OUT, "> $name.expected";
    my $udp_data = udp_data $data;
    printf OUT "dnslogger-forward: debug: Forwarded %d bytes.\ndnslogger-forward: Received data: %s\n",
    length ($udp_data) + 8 + 4, bin2hex "DNSXFR01\x51\x5b\xa1\x05$udp_data";
    close OUT;
}

for (my $length = 1; $length <= 5; ++$length) {
    my $header_length = 20 + 8;
    my $name = sprintf "default_auto-overlong-%03d", $header_length + $length;
    my $data = join ("", map chr, @data);
    $data .= ' ' x (512 + $header_length + $length - length ($data));
    fix_ip_length $data;
    fix_udp_length $data;

    open IN, "> $name.in";
    print IN $data;
    close IN;

    open OUT, "> $name.expected";
    my $udp_data = udp_data $data;
    printf OUT "dnslogger-forward: debug: Dropping overlong packet (81.91.161.5 -> 212.9.189.171, %u bytes).\n",
    $length + 512; 
    print OUT "dnslogger-forward: debug: No data received.\n";
    close OUT;
}

{
    my $name = "default_auto-virgin";

    my $data = join ("", map chr, @data);
    my $udp_data = udp_data $data;
    my $expected = sprintf 
	("dnslogger-forward: debug: Forwarded %d bytes.\ndnslogger-forward: Received data: %s\n",
	 length ($udp_data) + 8 + 4, bin2hex "DNSXFR01\x51\x5b\xa1\x05$udp_data");

    open IN, "> $name.in";
    print IN $data;
    close IN;
    open OUT, "> $name.expected";
    print OUT $expected;
    close OUT;
    
    $name = "default_auto-fixed-ip";
    fix_ip_length $data;
    open IN, "> $name.in";
    print IN $data;
    close IN;
    open OUT, "> $name.expected";
    print OUT $expected;
    close OUT;

    $name = "default_auto-fixed-udp";
    fix_udp_length $data;
    open IN, "> $name.in";
    print IN $data;
    close IN;
    open OUT, "> $name.expected";
    print OUT $expected;
    close OUT;
}
