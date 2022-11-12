#!/usr/bin/env python3

import atheris
import io
import sys

with atheris.instrument_imports():
    import dpkt


# Use the pcap reader

# If it succeeds, try the packet parsing example

@atheris.instrument_func
def TestOneInput(data):
    # Fuzz the PCAP reader
    try:
        with io.BytesIO(data) as f:
            f.name = 'fake_pcap'
            pcap = dpkt.pcap.Reader(f)

            if not pcap or not isinstance(pcap, dpkt.pcap.Reader):
                # We were unable to properly build a pcap reader, but did not crash
                return -1

            # Iterate through the pcap file
            for timestamp, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    dpkt.utils.inet_to_str(ip.src)
                    dpkt.utils.inet_to_str(ip.dst)
    except dpkt.Error:
        return -1
    except ValueError as e:
        if 'invalid tcpdump' in str(e):
            return -1




def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
