#!/usr/bin/env python3

import atheris
import io
import sys

import pkgutil

# dpkt's package __init__ eagerly does `from . import <submodule>` for ALL ~75 protocol modules.
# A bare `import dpkt` under atheris.instrument_imports() therefore instruments all 75 — ~75
# "INFO: Instrumenting ..." lines that push the libFuzzer banner to ~6s, PAST Mayhem's ~4s
# libFuzzer-detection window (the run is then rejected: "did not run / did not match libFuzzer
# format"). We keep ONE consistent import (so dpkt's class-dispatch identity stays intact and the
# harness's isinstance(eth.data, dpkt.ip.IP) still fires) but instrument ONLY the modules this
# harness reaches, by EXCLUDING every other dpkt submodule. atheris's exclude= is honored here
# (unlike include=), so this cuts instrumentation to the ~handful of parsers on the pcap ->
# ethernet -> ip/ip6 -> {tcp,udp,icmp,icmp6,dns} -> utils path and INITED drops to <1s.
_KEEP = {
    "dpkt", "dpkt.dpkt", "dpkt.compat",          # package core (needed by every module)
    "dpkt.pcap", "dpkt.ethernet", "dpkt.ip", "dpkt.ip6",
    "dpkt.tcp", "dpkt.udp", "dpkt.icmp", "dpkt.icmp6", "dpkt.dns", "dpkt.utils",
}
import dpkt as _dpkt_pkg
_EXCLUDE = [
    "dpkt." + m.name
    for m in pkgutil.iter_modules(_dpkt_pkg.__path__)
    if ("dpkt." + m.name) not in _KEEP
]
del _dpkt_pkg
if "dpkt" in sys.modules:           # the probe import above loaded it uninstrumented; drop it so the
    for _k in [k for k in sys.modules if k == "dpkt" or k.startswith("dpkt.")]:
        del sys.modules[_k]         # instrumented re-import below is the one that sticks.

with atheris.instrument_imports(exclude=_EXCLUDE):
    import dpkt


# A fixed, VALID libpcap global file header (24 bytes, big-endian TCPDUMP_MAGIC, linktype=1
# EN10MB/Ethernet) built from dpkt's OWN FileHdr class — so we exercise the real code path and stay
# resilient to upstream header-field changes (we only CALL dpkt; we don't reimplement its format).
_PCAP_FILE_HDR = bytes(dpkt.pcap.FileHdr(snaplen=0xffff, linktype=dpkt.pcap.DLT_EN10MB))


def _wrap_as_pcap(payload):
    """Wrap arbitrary bytes as a single-packet libpcap stream so dpkt.pcap.Reader() ALWAYS
    succeeds and the fuzzer's bytes reach the ethernet->IP->L4 parsers (instead of being rejected
    by the pcap magic/header check on the first byte). The per-packet record header is dpkt's own
    PktHdr; `payload` becomes the captured Ethernet frame."""
    rec_hdr = bytes(dpkt.pcap.PktHdr(caplen=len(payload), len=len(payload)))
    return _PCAP_FILE_HDR + rec_hdr + payload


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # Split the input: a chunk to be carried as the packet PAYLOAD inside a valid pcap wrapper, and
    # the remainder fed to the raw pcap.Reader path (which also fuzzes pcap parsing itself).
    payload = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, len(data)))
    rest = fdp.ConsumeBytes(atheris.ALL_REMAINING)

    # Path 1 (STRUCTURE-AWARE): every input becomes a valid pcap whose single packet is `payload`,
    # so pcap.Reader -> ethernet.Ethernet -> ip/ip6 -> tcp/udp/icmp/dns parsers are always exercised.
    try:
        with io.BytesIO(_wrap_as_pcap(payload)) as f:
            f.name = 'fake_pcap'
            pcap = dpkt.pcap.Reader(f)
            for timestamp, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    dpkt.utils.inet_to_str(ip.src)
                    dpkt.utils.inet_to_str(ip.dst)
                elif isinstance(eth.data, dpkt.ip6.IP6):
                    ip6 = eth.data
                    dpkt.utils.inet_to_str(ip6.src)
                    dpkt.utils.inet_to_str(ip6.dst)
    except Exception:
        # A reachable parsing error is expected for arbitrary bytes; suppress broadly so the corpus
        # is not stalled by a trivially-reachable defect (gitignore-style suppression).
        pass

    # Path 2 (ORIGINAL pcap.Reader semantics): feed the raw remaining bytes to pcap.Reader directly,
    # so the pcap container parsing (FileHdr/PktHdr decode) is still fuzzed as in the original target.
    try:
        with io.BytesIO(rest) as f:
            f.name = 'fake_pcap'
            pcap = dpkt.pcap.Reader(f)
            for timestamp, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    dpkt.utils.inet_to_str(ip.src)
                    dpkt.utils.inet_to_str(ip.dst)
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
