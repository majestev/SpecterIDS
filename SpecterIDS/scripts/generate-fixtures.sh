#!/usr/bin/env sh
set -eu

mkdir -p samples tests/fixtures tests/pcaps

make_record() {
    perl -e '
        my ($sec, $hex) = @ARGV;
        $hex =~ s/\s+//g;
        my $len = length($hex) / 2;
        print pack("VVVV", $sec, 0, $len, $len);
        print pack("H*", $hex);
    ' "$1" "$2"
}

write_pcap() {
    out="$1"
    shift
    perl -e 'print pack("VvvVVVV", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)' > "$out"
    sec=1
    for fixture in "$@"; do
        packet_hex="$(tr -d '[:space:]' < "$fixture")"
        make_record "$sec" "$packet_hex" >> "$out"
        sec=$((sec + 1))
    done
}

write_pcap samples/example.pcap tests/fixtures/ethernet_ipv4_tcp.hex
write_pcap tests/pcaps/ipv6.pcap tests/fixtures/ethernet_ipv6_tcp.hex
write_pcap tests/pcaps/malformed.pcap tests/fixtures/truncated.hex
write_pcap tests/pcaps/portscan.pcap \
    tests/fixtures/ethernet_ipv4_tcp.hex \
    tests/fixtures/ethernet_ipv4_tcp.hex \
    tests/fixtures/ethernet_ipv4_tcp.hex
write_pcap tests/pcaps/bruteforce.pcap tests/fixtures/ethernet_ipv4_tcp.hex
write_pcap tests/pcaps/synflood.pcap tests/fixtures/ethernet_ipv4_tcp.hex
write_pcap tests/pcaps/beaconing.pcap tests/fixtures/ethernet_ipv4_tcp.hex

# Error-path fixtures for offline-input hardening tests:
#   empty.pcap   -> valid global header, zero packet records (clean EOF)
#   corrupt.pcap -> invalid magic number, must be rejected without crashing
write_pcap tests/pcaps/empty.pcap
perl -e 'print pack("VvvVVVV", 0x12345678, 2, 4, 0, 0, 65535, 1)' > tests/pcaps/corrupt.pcap

printf 'generated samples/example.pcap and tests/pcaps/*.pcap\n'
