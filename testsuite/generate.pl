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

sub hex2bin (@) {
    return join "", map chr, map hex, @_;
}


die if checksum (hex2bin qw(00 01 f2 03 f4 f5 f6)) != 0x423;
die if checksum (hex2bin qw(00 01 f2 03 f4 f5 f6 f7)) != 0xd22;

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

{
    my $data = hex2bin qw(45 00 00 3a 00 00 40 00 40 11 b6 9d d4
				09 bd ab 51 5b a1 05 80 00 00 35 00 26
				84 4d 9e 97 01 00 00 01 00 00 00 00 00
				00 09 73 64 67 73 68 73 64 68 73 02 64
				65 00 00 01 00 01);
    fix_udp_checksum $data;	# fix broken checksum (kernel bug?)
    
    for my $flag qw(default A D) {
	my $name = "${flag}_auto-real-question";
	open IN, "> $name.in";
	print IN $data;
	close IN;

	open OUT, "> $name.expected";
	print OUT "dnslogger-forward: debug: Dropping question packet (212.9.189.171 -> 81.91.161.5).\n",;
	print OUT "dnslogger-forward: debug: No data received.\n";
	close OUT;
    }
}

{ 
    my $data = hex2bin qw(45 00 00 6e 04 8f 40 00 f6 11 fb d9 51 5b a1
			  05 d4 09 bd ab 00 35 80 00 00 5a 42 9a 9e 97
			  85 03 00 01 00 00 00 01 00 00 09 73 64 67 73
			  68 73 64 68 73 02 64 65 00 00 01 00 01 c0 16
			  00 06 00 01 00 01 51 80 00 28 01 61 03 6e 69
			  63 c0 16 03 6f 70 73 05 64 65 6e 69 63 c0 16
			  77 74 29 fa 00 00 2a 30 00 00 1c 20 00 36 ee
			  80 00 01 51 80);

    for my $flag qw(default A D) {
	my $name = "${flag}_auto-real-nxdomain";
	open IN, "> $name.in";
	print IN $data;
	close IN;
    }

    my $udp_data = udp_data $data;
    my $expected = sprintf 
	("dnslogger-forward: debug: Forwarded %d bytes.\ndnslogger-forward: Received data: %s\n",
	 length ($udp_data) + 8 + 4, bin2hex "DNSXFR01\x51\x5b\xa1\x05$udp_data");
    for my $flag qw(default A) {
	my $name = "${flag}_auto-real-nxdomain";
	open OUT, "> $name.expected";
	print OUT $expected;
	close OUT;
    }

    open OUT, "> D_auto-real-nxdomain.expected";
    print OUT "dnslogger-forward: debug: Dropping packet without answers (81.91.161.5 -> 212.9.189.171).\n",;
    print OUT "dnslogger-forward: debug: No data received.\n";
    close OUT;
}

{
    my $data = hex2bin qw(45 00 02 13 00 00 40 00 40 11 15 71 d4 09 bd
			  aa d4 09 bd ab 00 35 85 0a 01 ff 00 00 4e ef
			  87 80 00 01 00 0d 00 00 00 00 03 61 6f 6c 03
			  63 6f 6d 00 00 ff 00 01 c0 0c 00 06 00 01 00
			  00 0d f8 00 34 06 64 6e 73 2d 30 31 02 6e 73
			  c0 0c 0a 68 6f 73 74 6d 61 73 74 65 72 03 61
			  6f 6c 03 6e 65 74 00 77 74 29 18 00 00 07 08
			  00 00 01 2c 00 09 3a 80 00 00 02 58 c0 0c 00
			  0f 00 01 00 00 0d f8 00 11 00 0f 09 6d 61 69
			  6c 69 6e 2d 30 33 02 6d 78 c0 0c c0 0c 00 0f
			  00 01 00 00 0d f8 00 0e 00 0f 09 6d 61 69 6c
			  69 6e 2d 30 34 c0 71 c0 0c 00 0f 00 01 00 00
			  0d f8 00 0e 00 0f 09 6d 61 69 6c 69 6e 2d 30
			  31 c0 71 c0 0c 00 0f 00 01 00 00 0d f8 00 0e
			  00 0f 09 6d 61 69 6c 69 6e 2d 30 32 c0 71 c0
			  0c 00 10 00 01 00 00 01 14 00 aa a9 76 3d 73
			  70 66 31 20 69 70 34 3a 31 35 32 2e 31 36 33
			  2e 32 32 35 2e 30 2f 32 34 20 69 70 34 3a 32
			  30 35 2e 31 38 38 2e 31 33 39 2e 30 2f 32 34
			  20 69 70 34 3a 32 30 35 2e 31 38 38 2e 31 34
			  34 2e 30 2f 32 34 20 69 70 34 3a 32 30 35 2e
			  31 38 38 2e 31 35 36 2e 30 2f 32 33 20 69 70
			  34 3a 32 30 35 2e 31 38 38 2e 31 35 39 2e 30
			  2f 32 34 20 69 70 34 3a 36 34 2e 31 32 2e 31
			  33 36 2e 30 2f 32 33 20 69 70 34 3a 36 34 2e
			  31 32 2e 31 33 38 2e 30 2f 32 34 20 70 74 72
			  3a 6d 78 2e 61 6f 6c 2e 63 6f 6d 20 3f 61 6c
			  6c c0 0c 00 01 00 01 00 00 0d f8 00 04 98 a3
			  8e b8 c0 0c 00 01 00 01 00 00 0d f8 00 04 cd
			  bc 91 d5 c0 0c 00 01 00 01 00 00 0d f8 00 04
			  40 0c bb 18 c0 0c 00 02 00 01 00 00 0d f8 00
			  09 06 64 6e 73 2d 30 32 c0 2c c0 0c 00 02 00
			  01 00 00 0d f8 00 09 06 64 6e 73 2d 30 36 c0
			  2c c0 0c 00 02 00 01 00 00 0d f8 00 09 06 64
			  6e 73 2d 30 37 c0 2c c0 0c 00 02 00 01 00 00
			  0d f8 00 02 c0 25);

    for my $flag qw(default A D) {
	my $name = "${flag}_auto-TC";
	open IN, "> $name.in";
	print IN $data;
	close IN;

	my $udp_data = udp_data $data;
	my $expected = sprintf 
	    ("dnslogger-forward: debug: Forwarded %d bytes.\ndnslogger-forward: Received data: %s\n",
	     length ($udp_data) + 8 + 4, bin2hex "DNSXFR01\xd4\x09\xbd\xaa$udp_data");
	open OUT, "> $name.expected";
	print OUT $expected;
	close OUT;
    }
}
