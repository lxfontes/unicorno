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

## sample output

        [PUT] http://zzzz.service1.somecompany.com/property/execute/11 -> 201 Created : 56.220848ms
        [GET] http://zzzz.service2.somecompany.com/status/pingdom -> 200 OK : 76.234949ms
        [POST] http://nomnom.somecompany.com/service2/games/69/stream -> 201 Created : 77.598565ms
        [GET] http://zzzz.service2.somecompany.com/status/pingdom -> 200 OK : 79.429332ms
        [POST] http://nomnom.somecompany.com/service2/games/69/stream -> 201 Created : 72.239806ms
        [GET] http://zzzz.service2.somecompany.com/status/pingdom -> 200 OK : 55.561683ms
        [GET] http://zzzz.service2.somecompany.com/status/pingdom -> 200 OK : 66.028654ms
        [GET] http://vast.bp38.btrll.com/vast/385?n=1&br_w=301&br_h=251&br_adtype=0&br_autopl=1&br_sound=0&br_pageurl=ca.ign.com&br_i=lr -> 200 OK : 278.285001ms
        [GET] http://zzzz.service2.somecompany.com/status/pingdom -> 200 OK : 67.205569ms
        [PUT] http://zzzz.service1.somecompany.com/property/execute/11 -> 201 Created : 63.55534ms
        [POST] http://nomnom.somecompany.com/service2/games/69/stream -> 201 Created : 74.495483ms
        [GET] http://zzzz.service2.somecompany.com/status/pingdom -> 200 OK : 54.713016ms


## license

MIT
