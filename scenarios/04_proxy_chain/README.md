# Scenario 04 — Proxy Chain (Two Proxies)

## Topology

```
UAC (172.20.0.2) ──► Proxy1 (172.20.0.10) ──► Proxy2 (172.20.0.11) ──► UAS (172.20.0.3)
                                                     ▲
                                                  capture
```

Capture is on Proxy2's network namespace, showing the Proxy1↔Proxy2 and
Proxy2↔UAS legs.

## Concepts

| Concept | Description |
|---------|-------------|
| **Proxy chain** | Multiple proxies in sequence. Each adds its Via header. |
| **3 Via headers** | INVITE at UAS has Via: Proxy2, Via: Proxy1, Via: UAC (newest on top). |
| **$du (destination URI)** | Proxy1 uses `$du` to override the next-hop to Proxy2 without changing the Request-URI. |
| **No Record-Route** | Without Record-Route, in-dialog requests (ACK, BYE) should go directly UAC→UAS in real SIP. See scenario 05 for Record-Route. |

## How to Run

```bash
python3 labctl.py run 04_proxy_chain
```

## What to Look for in the PCAP

### 1. Via Stacking (3 Layers!)

```bash
# INVITE arriving at UAS from Proxy2 — should have 3 Via headers
tshark -r captures/04_proxy_chain.pcap -Y "sip.Method==INVITE && ip.dst==172.20.0.3" -T fields -e sip.Via
```

The Via stack (top-to-bottom = newest-to-oldest):
1. `Via: SIP/2.0/UDP 172.20.0.11` — added by Proxy2
2. `Via: SIP/2.0/UDP 172.20.0.10` — added by Proxy1
3. `Via: SIP/2.0/UDP 172.20.0.2:5060` — added by UAC

### 2. Via Consumption on Responses

Responses travel back through the Via stack in reverse. Each proxy strips the
topmost Via (its own) before forwarding:

```bash
# 200 OK from UAS→Proxy2: 3 Via headers
tshark -r captures/04_proxy_chain.pcap -Y "sip.Status-Code==200 && ip.src==172.20.0.3" -T fields -e sip.Via

# 200 OK from Proxy2→Proxy1: 2 Via headers (Proxy2's Via stripped)
tshark -r captures/04_proxy_chain.pcap -Y "sip.Status-Code==200 && ip.src==172.20.0.11 && ip.dst==172.20.0.10" -T fields -e sip.Via
```

### 3. Full Message Flow

```bash
tshark -r captures/04_proxy_chain.pcap -Y sip -T fields -e frame.number -e ip.src -e ip.dst -e sip.Method -e sip.Status-Code
```

## Key Kamailio Configs

**Proxy1** — overrides destination to Proxy2:
```
$du = "sip:172.20.0.11:5060";   # Next hop: Proxy2
t_relay();
```

**Proxy2** — relays to Request-URI (UAS):
```
t_relay();   # No $du override: forwards to R-URI
```

## Exercises

1. How many Via headers does the INVITE have at Proxy2? At UAS?
2. Trace a 200 OK response back from UAS to UAC: at each hop, which Via is stripped?
3. Do ACK and BYE also have 3 Via headers? Why? (Hint: look at scenario 05 for the difference.)
4. What would happen if you added a third proxy?
