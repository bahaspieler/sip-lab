# Scenario 05 — Record-Route and Route Headers

## Topology

```
UAC (172.20.0.2) ──► Proxy1 (172.20.0.10) ──► Proxy2 (172.20.0.11) ──► UAS (172.20.0.3)
                                                     ▲
                                                  capture
```

Same topology as scenario 04, but both proxies now add `record_route()`.

## Concepts

| Concept | Description |
|---------|-------------|
| **Record-Route** | A proxy adds this header to the INVITE so it stays in the dialog path for subsequent requests (ACK, BYE). |
| **Route** | The UAC constructs Route headers from the Record-Route received in the 200 OK. These tell subsequent requests which proxies to traverse. |
| **Loose Routing (`lr`)** | The `;lr` parameter on Record-Route URIs indicates RFC 3261 loose routing. The proxy processes its own Route entry and forwards to the next. |
| **Route Set** | The ordered list of proxies that in-dialog requests must traverse. Built from Record-Route headers. |

## How to Run

```bash
python3 labctl.py run 05_record_route
```

## What to Look for in the PCAP

### 1. Record-Route Accumulation on INVITE

```bash
# INVITE from Proxy1→Proxy2: 1 Record-Route (Proxy1's)
tshark -r captures/05_record_route.pcap -Y "sip.Method==INVITE && ip.src==172.20.0.10" -T fields -e sip.Record-Route

# INVITE from Proxy2→UAS: 2 Record-Routes (Proxy2 + Proxy1)
tshark -r captures/05_record_route.pcap -Y "sip.Method==INVITE && ip.dst==172.20.0.3" -T fields -e sip.Record-Route
```

### 2. Record-Route in Responses

The UAS copies Record-Route into 180 and 200 OK (required by RFC 3261):

```bash
tshark -r captures/05_record_route.pcap -Y "sip.Status-Code==200 && sip.CSeq.method==INVITE" -T fields -e ip.src -e ip.dst -e sip.Record-Route
```

### 3. Route Headers on ACK and BYE (THE KEY DIFFERENCE!)

Compare with scenario 04 — ACK and BYE now have **Route headers**:

```bash
# ACK from Proxy1→Proxy2: has Route header pointing to Proxy2
tshark -r captures/05_record_route.pcap -Y "sip.Method==ACK" -T fields -e ip.src -e ip.dst -e sip.Route

# BYE follows the same route set
tshark -r captures/05_record_route.pcap -Y "sip.Method==BYE" -T fields -e ip.src -e ip.dst -e sip.Route
```

The Route processing at each hop:
1. **UAC** sends ACK with `Route: <sip:P1;lr>, <sip:P2;lr>` to P1
2. **P1** strips its own Route entry, sees next hop is P2, forwards with `Route: <sip:P2;lr>`
3. **P2** strips its own Route entry, no more Routes, forwards to Request-URI (UAS)

### 4. Full Comparison with Scenario 04

```bash
# Scenario 04: ACK has NO Route headers (proxies not in dialog path)
tshark -r captures/04_proxy_chain.pcap -Y "sip.Method==ACK" -T fields -e sip.Route

# Scenario 05: ACK HAS Route headers (proxies stay in dialog path)
tshark -r captures/05_record_route.pcap -Y "sip.Method==ACK" -T fields -e sip.Route
```

## Key Kamailio Config (additions over scenario 04)

```
loadmodule "rr.so"
loadmodule "siputils.so"

request_route {
    # In-dialog requests: use loose_route() to follow Route headers
    if (has_totag()) {
        if (loose_route()) {
            t_relay();
            exit;
        }
    }

    # Initial requests: add Record-Route
    record_route();

    # Forward as before...
}
```

## Custom SIPp Scenarios

This scenario uses custom SIPp XML files:
- `sipp/uac_record_route.xml` — UAC that stores Record-Route via `rrs="true"` and
  expands `[routes]` into Route headers for ACK and BYE
- `sipp/uas_record_route.xml` — UAS that copies Record-Route from INVITE into
  180/200 responses (required by RFC 3261 but not done by SIPp's built-in UAS)

## Exercises

1. How many Record-Route headers does the INVITE have when it reaches UAS?
2. The UAC receives 200 OK with Record-Route. In what order does it construct the Route set? (Hint: RFC 3261 §12.1.2 says the caller reverses the order.)
3. What does the `;lr` parameter mean? What would happen without it?
4. If you removed `record_route()` from Proxy1 only, which proxy would still be in the BYE path?
5. In what real-world scenario is Record-Route essential? (Hint: think about NAT, billing, or call recording.)
