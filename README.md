# unicorno

Packet sniffer focused on HTTP request / response matching.

This is a troubleshooting tool for this specific scenario:
- short-lived http requests. Either `Connection: close` or a single request/response per 5-tuple.
- no websockets :)
- no https

## usage

Requires root.

      # ./unicorno  -h
      Usage of ./unicorno:
        -assembly_debug_log=false: If true, the code.google.com/p/gopacket/tcpassembly library will log verbose debugging information (at least one line per packet)
        -assembly_memuse_log=false: If true, the code.google.com/p/gopacket/tcpassembly library will log information regarding its memory use every once in a while.
        -d="tcp and dst port 80": BPF filter for pcap
        -i="eth0": Interface to get packets from
        -l=1600: SnapLen for pcap packet capture
        -s="tcp and src port 80": BPF filter for pcap

## license

MIT
