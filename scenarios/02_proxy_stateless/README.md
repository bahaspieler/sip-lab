# Scenario 02 — Stateless Proxy

## Topology

```
UAC (172.20.0.2) ──► Kamailio Proxy (172.20.0.10) ──► UAS (172.20.0.3)
                          ▲
                       capture
```

The capture container shares the **proxy's** network namespace, so it sees
both legs of every SIP exchange: UAC↔Proxy and Proxy↔UAS.

## Concepts

| Concept | Description |
|---------|-------------|
| **Stateless proxy** | Forwards requests/responses without keeping transaction state. Uses Kamailio's core `forward()` function. |
| **Via header stacking** | The proxy adds its own Via before forwarding, then strips it from responses. |
| **Max-Forwards** | The proxy decrements Max-Forwards to prevent routing loops. |

## How to Run

```bash
python3 labctl.py run 02_proxy_stateless
```

## What to Look for in the PCAP

Open `captures/02_proxy_stateless.pcap` in Wireshark or tshark.

### 1. Via Header Stacking

Compare the INVITE on both legs:

```bash
# INVITE from UAC → Proxy (1 Via header)
tshark -r captures/02_proxy_stateless.pcap -Y "sip.Method==INVITE && ip.src==172.20.0.2" -T fields -e sip.Via

# INVITE from Proxy → UAS (2 Via headers: Proxy + UAC)
tshark -r captures/02_proxy_stateless.pcap -Y "sip.Method==INVITE && ip.src==172.20.0.10" -T fields -e sip.Via
```

### 2. No 100 Trying

The stateless proxy does **not** generate 100 Trying. Compare with scenario 03:

```bash
# Count 100 responses — should be 0 for stateless proxy
tshark -r captures/02_proxy_stateless.pcap -Y "sip.Status-Code==100" 2>/dev/null | wc -l
```

### 3. Response Reordering (Stateless Side-effect)

With a stateless proxy, 200 OK may arrive at the UAC before 180 Ringing because
`forward()` processes each message independently. Look for the 180 arriving
*after* ACK — this is visible in the pcap and demonstrates why stateless proxies
are simpler but less predictable.

## Key Kamailio Config

```
request_route {
    if (!maxfwd_process("10")) { sl_send_reply("483", "Too Many Hops"); exit; }
    forward();   # Stateless: no transaction, no 100 Trying
}
```

## Exercises

1. Count the Via headers on the INVITE arriving at UAS. How many are there?
2. Trace the response path: which Via is stripped at each hop?
3. Compare this pcap with scenario 03 — what extra packet does the stateful proxy produce?
