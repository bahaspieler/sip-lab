# Scenario 01 — Basic UAC ↔ UAS Call

## Topology

```
┌──────────┐         sipnet (bridge)         ┌──────────┐
│ SIPp UAC │◄───────────────────────────────►│ SIPp UAS │
│ (caller) │         UDP port 5060           │ (callee) │
└──────────┘                                 └──────────┘
      ▲
      │  network_mode: service:sipp_uac
┌─────┴────┐
│ capture  │  tcpdump → /captures/*.pcap
└──────────┘
```

No proxy, no registrar — a direct SIP call between two User Agents.
The capture container shares the UAC's network namespace, so tcpdump
sees all SIP traffic from the UAC's perspective.

## How to run

```bash
# From the repo root:
python3 labctl.py run_basic --pcap basic.pcap

# Or manually with this scenario's compose file:
python3 labctl.py -f scenarios/01_basic_call/docker-compose.yml run_basic --pcap basic.pcap
```

## Expected packets (in order)

| # | Direction | Message | Notes |
|---|-----------|---------|-------|
| 1 | UAC → UAS | INVITE | Contains SDP offer (codec list) |
| 2 | UAS → UAC | 100 Trying | Provisional, hop-by-hop |
| 3 | UAS → UAC | 180 Ringing | Provisional, end-to-end |
| 4 | UAS → UAC | 200 OK | Final response, contains SDP answer |
| 5 | UAC → UAS | ACK | Completes the INVITE transaction |
| 6 | UAC → UAS | BYE | Terminates the dialog (after ~4s pause) |
| 7 | UAS → UAC | 200 OK | Confirms BYE |

> **Note**: In this lab, the UAC (caller) always sends BYE because that is how SIPp's
> built-in `-sn uac` scenario works. In real SIP, **either party** (caller or callee) can
> send BYE to end the dialog. In practice, either party can send BYE — the
> direction depends on application logic, not the protocol.

## Headers to study

Open the pcap in Wireshark (`File → Open → captures/basic.pcap`) and inspect:

### Mandatory SIP headers (present in every message)

| Header | Purpose | Example |
|--------|---------|---------|
| **Via** | Records the transport path; used for routing responses back | `Via: SIP/2.0/UDP 172.20.0.2:5060;branch=z9hG4bK-...` |
| **From** | Identifies the originator; includes a `tag` parameter | `From: <sip:sipp@172.20.0.2>;tag=12345` |
| **To** | Identifies the destination; gets a `tag` in responses | `To: <sip:sipp@172.20.0.3>` → response adds `;tag=...` |
| **Call-ID** | Unique identifier for the entire dialog | `Call-ID: 1-12345@172.20.0.2` |
| **CSeq** | Sequence number + method; identifies the transaction | `CSeq: 1 INVITE`, `CSeq: 2 BYE` |
| **Max-Forwards** | Hop limit (decremented by proxies, starts at 70) | `Max-Forwards: 70` |
| **Contact** | Direct URI to reach this UA for future requests | `Contact: <sip:sipp@172.20.0.2:5060>` |

### SDP body (in INVITE and 200 OK)

Look for `Content-Type: application/sdp` and the SDP body:

```
v=0
o=- 12345 12345 IN IP4 172.20.0.2
s=-
c=IN IP4 172.20.0.2
t=0 0
m=audio 6000 RTP/AVP 0
a=rtpmap:0 PCMU/8000
```

Key SDP fields:
- `c=` — connection address (where to send RTP)
- `m=` — media line (port, protocol, codec payload type)
- `a=rtpmap:` — codec name mapping (0 = PCMU = G.711 μ-law)

## Key concepts to verify

### 1. Dialog identification

A SIP **dialog** is identified by the triple: `Call-ID` + `From-tag` + `To-tag`.

- Check: the `To` header in the INVITE has no tag.
- Check: the `To` header in 200 OK has a tag added by the UAS.
- After 200 OK, all subsequent messages (ACK, BYE) use both tags.

### 2. Transaction matching

A SIP **transaction** is identified by the `Via: branch` parameter.

- Check: INVITE, 100, 180, and 200 OK all share the same `branch` value.
- Check: ACK to 2xx has a **different** branch (it's a separate transaction in RFC 3261).
- Check: BYE and its 200 OK share their own `branch` value.
- Total transactions in this call: **3** (INVITE, ACK, BYE).

### 3. SDP offer/answer

- The INVITE contains the **offer** (UAC's supported codecs).
- The 200 OK contains the **answer** (UAS's chosen codec).
- Both should agree on at least one codec (typically PCMU/G.711).

## tshark commands

```bash
# Show all SIP packets (summary)
tshark -r captures/basic.pcap -Y sip

# Show full decoded SIP messages (like Wireshark packet details)
tshark -r captures/basic.pcap -Y sip -V

# Show only INVITE messages
tshark -r captures/basic.pcap -Y "sip.Method == INVITE"

# Show Via headers for each packet
tshark -r captures/basic.pcap -Y sip -T fields \
  -e frame.number -e sip.Method -e sip.Status-Code -e sip.Via

# Show dialog identifiers (Call-ID, From-tag, To-tag)
tshark -r captures/basic.pcap -Y sip -T fields \
  -e frame.number -e sip.Call-ID -e sip.from.tag -e sip.to.tag

# Show CSeq to identify transactions
tshark -r captures/basic.pcap -Y sip -T fields \
  -e frame.number -e sip.CSeq -e sip.Method -e sip.Status-Code

# Show a specific packet in full detail (e.g., packet 1)
tshark -r captures/basic.pcap -Y "frame.number == 1" -V

# Count packets by SIP method/status
tshark -r captures/basic.pcap -Y sip -T fields -e sip.Method -e sip.Status-Code \
  | sort | uniq -c

# Extract SDP body from INVITE
tshark -r captures/basic.pcap -Y "sip.Method == INVITE" -T fields -e sip.msg_body
```

## Exercises

1. **Find the Call-ID**: What is the Call-ID for this dialog? Is it the same in every message?
2. **Count transactions**: How many distinct `Via: branch` values are there? What does each correspond to?
3. **Dialog tags**: At which message does the To-tag first appear? Why?
4. **SDP codec**: What codec was negotiated? What is its RTP payload type number?
5. **CSeq numbering**: What are the CSeq numbers for INVITE, ACK, and BYE? Why does ACK have the same CSeq as INVITE?
6. **Max-Forwards**: What value does Max-Forwards have in the INVITE? What would happen if a proxy chain decremented it to 0?
7. **Contact vs From**: How does the Contact header differ from the From header? When would a UA use the Contact URI?
