# sip-lab

A Docker-based lab environment for studying the SIP protocol hands-on. It uses
SIPp for traffic generation, Kamailio for proxy scenarios, and tcpdump for
packet capture. You run a scenario, get a pcap, and inspect it in Wireshark or
tshark.

## Prerequisites

- Docker and Docker Compose (v2)
- Python 3.x
- Wireshark or tshark (for pcap analysis)

## Quick Start

```bash
# List available scenarios
python3 labctl.py list

# Run a scenario (captures are saved to ./captures/)
python3 labctl.py run 01_basic_call

# Run with options
python3 labctl.py run 03_proxy_stateful --keep --verbose
```

Each scenario brings up its own Docker Compose topology, runs a SIPp call,
captures the SIP traffic, and tears everything down.

## Scenarios

| # | Name | What It Demonstrates |
|---|------|----------------------|
| 01 | Basic Call | Direct UAC-to-UAS call. SDP offer/answer, dialog setup, BYE teardown. |
| 02 | Stateless Proxy | Single Kamailio proxy using `forward()`. Via stacking, no 100 Trying. |
| 03 | Stateful Proxy | Single Kamailio proxy using `t_relay()`. Transaction state, auto 100 Trying. |
| 04 | Proxy Chain | Two proxies in series. Three Via headers, response path via Via consumption. |
| 05 | Record-Route | Two proxies with `record_route()`. Route headers on ACK/BYE keep proxies in the dialog path. |

Each scenario has its own README with the expected packet flow, tshark
commands, and exercises.

## Project Layout

```
sip-lab/
  labctl.py                     # Lab controller (orchestration + CLI)
  docker-compose.yml            # Base topology (UAC + UAS + capture)
  scenarios/
    01_basic_call/
      docker-compose.yml        # Self-contained topology for this scenario
      scenario.json             # Config read by labctl.py (targets, flags)
      README.md                 # What to look for in the pcap
    02_proxy_stateless/
      docker-compose.yml
      kamailio.cfg              # Kamailio config for this scenario
      scenario.json
      README.md
    ...
  sipp/
    uac_proxy.xml               # Custom SIPp UAC scenario (proxy-tolerant)
    uac_record_route.xml        # UAC with Route header support
    uas_record_route.xml        # UAS that copies Record-Route into responses
    uac_callee_bye.xml          # UAC that waits for BYE from callee
    uas_callee_bye.xml          # UAS that sends BYE after a pause
  captures/                     # pcap output directory (gitignored)
```

## How Captures Work

Each scenario's `docker-compose.yml` includes a **capture** container
(nicolaka/netshoot) that shares the network namespace of a chosen service
via `network_mode: "service:<target>"`. The controller starts tcpdump inside
this container before triggering the SIPp call, then stops it after the call
completes.

The capture point varies by scenario:
- **Scenario 01**: Attached to the UAC -- sees the UAC's view of the call.
- **Scenarios 02-03**: Attached to the proxy -- sees both legs (UAC-Proxy and Proxy-UAS).
- **Scenarios 04-05**: Attached to Proxy2 -- sees accumulated Via/Record-Route headers from the full chain.

Captures are written to `./captures/<scenario>.pcap` via a volume mount.

## labctl.py

The controller handles the orchestration so you don't have to remember the
startup sequence. Core commands:

```bash
labctl.py list                          # Show available scenarios
labctl.py run <scenario>                # Run a scenario and capture traffic
labctl.py run_basic --pcap basic.pcap   # Simple UAC/UAS call (no proxy)
labctl.py up / down / ps / logs         # Docker Compose passthrough
labctl.py exec <container> -- <cmd>     # Exec into a running container
```

Run `python3 labctl.py -h` for full usage.
