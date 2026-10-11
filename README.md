# Midea L1PB20-C28WM(WIFI) network investigation

Investigation date: **2026-10-11**. This README records the completed captures,
commands, exact selected wire payloads, offline checks, source research, and
remaining unknowns. No new live investigation is required to reproduce the
offline analysis below.

**Result:** the boiler maintains a proprietary `8370`-framed connection to
`module-us.msmartlife.net:28443`. The reboot capture includes its initial
cloud type `8 → 1 → 2` exchange. The framing and SHA-256 trailers of types 8
and 1 were verified. Discovery broadcasts were successfully decrypted.
**The cloud session key, its derivation, and cloud application plaintext have
not been recovered.**

## 1. Device and environment

| Item | Value | Evidence |
| --- | --- | --- |
| Appliance | `L1PB20-C28WM(WIFI)` gas central-heating boiler | Owner; Midea product page |
| Appliance IP | `192.168.200.133` | Capture |
| Appliance MAC | `b8:0b:da:ce:a2:30` | Ethernet, DHCP, decrypted discovery |
| DHCP/discovery name | `midea_e6_0394` | DHCP and decrypted discovery |
| Appliance category | `0xE6` | Discovery and serial/name; consistent with boiler implementation |
| Device ID | `151732607790550` | Inner discovery header, six bytes interpreted little-endian |
| Serial | `0000E65412760002446141A00394N925` | Decrypted discovery |
| Advertised LAN TCP port | `6444` | Decrypted discovery |
| Router / gateway / DNS | `192.168.200.1` | UDP sender and DHCP ACK |
| Router model | `RB962UiGS-5HacT2HnT` | Owner's RouterOS prompt |
| Router capture interface | `wlan2` | Owner's sniffer configuration |
| Mac capture receiver | `192.168.200.164`, interface `en0` | `ifconfig en0` |
| TZSP destination | UDP `37008` | Router config and received stream |
| Workspace | `/Users/user/Projects/Midea` | Local environment |
| Wi-Fi module model/chipset/firmware | **Unknown** | No matching public firmware identified |

Midea's product listing confirms the boiler model and Wi-Fi support. The
model number alone does not identify the Wi-Fi module or its root credentials.

## 2. Capture setup and exact procedure

The owner supplied this RouterOS configuration:

```text
[user@RB962UiGS-5HacT2HnT] /tool/sniffer> print
                     only-headers: no
                     memory-limit: 100KiB
                    memory-scroll: yes
                        file-name:
                       file-limit: 70000KiB
                streaming-enabled: yes
                 streaming-server: 192.168.200.164:37008
                  max-packet-size: 2048
                    filter-stream: yes
                 filter-interface: wlan2
               filter-mac-address:
           filter-src-mac-address:
           filter-dst-mac-address:
              filter-mac-protocol:
                filter-ip-address: 192.168.200.133/32
```

The router streams captured frames using TZSP. The UDP envelope is not the
boiler's application traffic. The receiver removes that envelope and writes
ordinary Ethernet packets to PCAP.

Ensure the RouterOS sniffer is running:

```routeros
/tool/sniffer/start
```

Local tool/interface checks used:

```bash
cd /Users/user/Projects/Midea
command -v tcpdump
command -v tshark
command -v python3
ifconfig en0
tcpdump -D
```

Installed executables found: `/usr/sbin/tcpdump`, `/usr/local/bin/tshark`, and
`/opt/homebrew/bin/python3`.

### Attempted direct tcpdump capture

```bash
tcpdump -i en0 -nn -s 0 -U -w midea-tzsp.pcap 'udp dst port 37008'
```

This failed inside the agent sandbox:

```text
tcpdump: (cannot open BPF device) /dev/bpf0: Operation not permitted
```

Binding a UDP socket from the sandbox also failed with
`PermissionError: [Errno 1] Operation not permitted`. Therefore the **owner
ran both captures in their Mac terminal**, using [capture_tzsp.py](capture_tzsp.py).
No usable outer TZSP PCAP was created.

### Capture 1: established connection, 180 seconds

Exact commands executed by the owner:

```bash
cd /Users/user/Projects/Midea
python3 capture_tzsp.py --seconds 180
tcpdump -nn -tttt -r midea-inner.pcap 'host 192.168.200.133'
```

Receiver output:

```text
Listening on 192.168.200.164:37008 for 180s; saving midea-inner.pcap
First Ethernet packet received from 192.168.200.1
Saved 212 packets; senders: {'192.168.200.1': 212}; rejected: {}
```

### Capture 2: reboot / handshake, 120 seconds

Exact command executed by the owner:

```bash
cd /Users/user/Projects/Midea
python3 capture_tzsp.py --seconds 120 --output midea-reboot.pcap
```

The owner rebooted the device during this capture, after the receiver was
listening. The exact physical reboot time was not recorded.

```text
Listening on 192.168.200.164:37008 for 120s; saving midea-reboot.pcap
First Ethernet packet received from 192.168.200.1
Saved 283 packets; senders: {'192.168.200.1': 283}; rejected: {}
```

For future captures, choose a **new output filename**: the receiver opens its
output in `wb` mode and would overwrite an existing capture with that name.

### Receiver behavior and visibility limits

`capture_tzsp.py` uses Python's standard library only. It binds UDP on
`192.168.200.164:37008`, accepts TZSP version 1 / packet type 0 / Ethernet
encapsulation 1, skips variable-length tags up to the end tag, and writes
Ethernet frames to a little-endian PCAP with microsecond timestamps.

Timestamps are **Mac receive times**, not router packet timestamps. Stream
buffering and scheduling can compress inter-packet intervals; ACK timings
are approximate. Zero rejected datagrams does not prove zero upstream loss.
The receiver does not preserve TZSP tags or the original UDP envelope.

The RouterOS filter is for one IPv4 address on one interface. It is not a
complete capture of every possible appliance packet: broadcast DHCP requests,
ARP, IPv6, or traffic on other interfaces may be absent. The 2048-byte router
packet-size setting is another possible truncation limit, although the
selected handshake messages are fully present.

## 3. Reproduce the packet analysis

These are offline reads and work without live capture-device access:

```bash
# Conversation totals and protocol hierarchy; -n avoids hostname resolution.
tshark -n -r midea-inner.pcap -q -z io,phs -z conv,tcp -z conv,udp
tshark -n -r midea-reboot.pcap -q -z io,phs -z conv,tcp -z conv,udp

# Full payload hex in tcpdump.
tcpdump -nn -XX -r midea-inner.pcap -c 6

# DNS, DHCP, setup/teardown, and Wireshark TCP analysis flags.
tshark -n -r midea-reboot.pcap \
  -Y 'dns || dhcp || tcp.flags.syn == 1 || tcp.flags.fin == 1 || tcp.flags.reset == 1 || tcp.analysis.flags' \
  -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Info

# Check TCP analysis flags separately.
tshark -n -r midea-inner.pcap -Y 'tcp.analysis.flags' \
  -T fields -e frame.number -e _ws.col.Info
tshark -n -r midea-reboot.pcap -Y 'tcp.analysis.flags' \
  -T fields -e frame.number -e _ws.col.Info

# DHCP detail, including hostname, lease, DNS, and gateway.
tshark -n -r midea-inner.pcap -Y dhcp -V

# Export first capture application payloads.
tshark -n -r midea-inner.pcap -Y 'tcp.len > 0' -T fields \
  -e frame.time_epoch -e ip.src -e tcp.len -e tcp.payload > midea-payloads.tsv

# Export reboot application payloads, keeping frame numbers and endpoints.
tshark -n -r midea-reboot.pcap -Y 'tcp.len > 0' -T fields \
  -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e tcp.len -e tcp.payload > midea-reboot-payloads.tsv

# Export all broadcast bodies.
tshark -n -r midea-reboot.pcap -Y 'udp.port == 15000' -T fields \
  -e frame.time_relative -e udp.payload > midea-reboot-broadcasts.tsv

# Inspect the three handshake messages, including Ethernet/IP/TCP bytes.
tshark -n -r midea-reboot.pcap \
  -Y 'frame.number == 26 || frame.number == 28 || frame.number == 30' -x

# Initial capture ACK timing samples.
tshark -n -r midea-inner.pcap -Y 'tcp.analysis.ack_rtt' -T fields \
  -e tcp.analysis.ack_rtt > midea-ack-times.txt
python3 - <<'PYCODE'
import statistics
samples = [float(s) for s in open('midea-ack-times.txt') if s.strip()]
print('samples:', len(samples))
print('median/min/max milliseconds:',
      *(round(v * 1000, 2) for v in
        (statistics.median(samples), min(samples), max(samples))))
PYCODE
```

## 4. Established-connection findings

First packet: `2026-10-11 14:00:34.619323 +04:00`.
Last packet: `2026-10-11 14:03:25.461923 +04:00`.
Packet span: **170.8426 seconds**, within the 180-second receiver window.

| Item | Result |
| --- | --- |
| Total | 212 packets; 29,074 Ethernet-frame bytes |
| TCP | 210 packets, one established connection |
| TCP endpoints | `192.168.200.133:54273 ↔ 35.71.136.152:28443` |
| Device TCP application data | 100 payload-bearing packets, 16,248 bytes |
| Server TCP application data | 7 payload-bearing packets, 794 bytes |
| Device payload sizes | 93 × 166; 3 × 102; 1 × 150; 3 × 118 bytes |
| Server payload sizes | 3 × 102; 3 × 118; 1 × 134 bytes |
| DHCP | One request/ACK renewal pair |
| ACK timing samples | 106; median 68.12 ms; min 0.04 ms; max 198.82 ms |

All 107 payload-bearing TCP packets begin with `8370`, and each contains a
complete frame whose length field plus 8 equals its TCP payload length.
No TCP analysis flags, SYN, FIN, or RST were observed in this first capture.
The last outgoing payload's ACK may fall outside the capture window.

Observed traffic patterns, with **interpretations not proven by decryption**:

- Repeated 166-byte device messages, often about one second apart: consistent
  with reporting traffic, but actual contents are unknown.
- 102-byte exchanges at `14:00:52`, `14:02:12`, and `14:02:52`: consistent
  with keepalives. Intervals are 80 s then 40 s; no fixed cadence is proven.
- Bidirectional burst around `14:01:31–32`: possibly cloud/app interaction;
  no action was correlated with this burst.

DHCP renewal at `14:02:31.754679` retained the appliance address. ACK options:
subnet `255.255.255.0`, gateway/DNS/server `192.168.200.1`, lease **600 seconds**.

No DNS lookup or local-control connection appeared in this capture. It started
mid-session, so this absence does not mean the appliance never uses them.

## 5. Reboot findings and timeline

First packet: `2026-10-11 14:08:03.775319 +04:00`.
Last packet: `2026-10-11 14:10:02.889211 +04:00`.
Packet span: **119.113892 seconds**, within the 120-second receiver window.

| Traffic | Packets | Details |
| --- | --- | --- |
| Old TCP session | 18 | Device port 54273, cloud port 28443 |
| New TCP session | 216 | Device port 60806, cloud port 28443 |
| DNS | 3 | Two identical queries and one response |
| DHCP | 2 | Offer and ACK; client requests not present in filtered stream |
| UDP broadcasts | 44 | `192.168.200.133:65471 → 255.255.255.255:15000` |
| Total | 283 | 43,332 Ethernet-frame bytes |

All 44 captured broadcast payloads differ at the byte level. Only the first
broadcast was decrypted during this investigation; no interpretation of the
changing broadcast fields has been established.

Times below are seconds relative to the **first captured packet**, not to
receiver start or the physical reboot.

| Frame | Relative time | Event |
| --- | --- | --- |
| 17 | 29.752054 | DHCP offer for 192.168.200.133 |
| 18 | 29.760385 | DHCP ACK |
| 19 | 31.633581 | A query for module-us.msmartlife.net |
| 20 | 31.722227 | First UDP discovery broadcast |
| 21 | 31.722340 | Second identical DNS query |
| 22 | 31.722382 | DNS response |
| 23 | 31.722418 | New TCP SYN, appliance port 60806 |
| 24 | 31.780386 | SYN/ACK, about 58 ms later |
| 25 | 31.783736 | ACK completing TCP handshake |
| 26 | 31.934680 | Device type 8, 424 bytes |
| 28 | 32.151337 | Server type 1, 168 bytes |
| 30 | 32.769246 | Device type 2, 54 bytes |
| 31 | 32.769384 | First new-session device type 3, 150 bytes |
| 70 | 36.964627 | Cloud FIN on the old port-54273 session |
| 71 | 36.964869 | Device RST/ACK on the old session |

DNS result:

```text
module-us.msmartlife.net
  CNAME af60e0ba9874374e2.awsglobalaccelerator.com   TTL 300
  A     35.71.136.152                             TTL 192
  A     52.223.47.215                             TTL 192
```

The appliance selected `35.71.136.152:28443`. This identifies the observed
endpoint; it does not locate the actual backend or prove a geographic region.

No TCP analysis flags were reported. The old session FIN/RST is consistent
with reboot cleanup; the new session continued exchanging application data.

## 6. Framing and exact selected TCP payloads

Hex blocks below contain **application-layer TCP payload bytes only**, excluding
Ethernet/IP/TCP headers. Lines are wrapped for readability; concatenating them
recovers the original bytes exactly. The PCAP and TSV exports retain every
captured packet; selected messages are reproduced here in full.

The known LAN V3 framing uses:

| Offset | Field |
| --- | --- |
| 0–1 | Magic `83 70` |
| 2–3 | Big-endian length; complete frame size is this value + 8 |
| 4 | Fixed marker `20` |
| 5 | High nibble: padding count; low nibble: message type |
| 6 onward | Message-specific body, possibly encrypted |

For LAN encrypted messages, the counter is inside the AES-CBC encrypted body,
not a clear two-byte field preceding ciphertext. For clear handshake messages,
bytes 6–7 can be a counter. These conventions are confirmed in LAN source;
cloud field semantics beyond the observed structure remain partly inferred.

This is Midea's proprietary framing. “V3” is not TLS 1.3. The captured TCP
payloads are `8370` packets rather than TLS records.

### Representative initial-capture type 3 message — 166 bytes

```text
8370009e2063d7c067353ec1b903f87690be10bf9d325473ab8358f4a0591f9d
0f1fab4cdc74046dd555ae3e6343a808397c1f8e511aa6e1e5fb3d1fac21f66f
acf35e09b98700755fcac07d64a77674b23bf95b9e2c4046d943c09204768b8d
d30597d6a4828de5ff2d707b099b839fa03de58f58d7beb403437abaaa04ab94
2606c9d25bb2d058ebe2b5ec8b20d6cde2bb5b2441227bfd24f9f5262fe5a7e6
5e1caae4eb5a
```

### Cloud exchange frame 26 — type 8, 424 bytes

```text
837001a02008000069e57ec13a20ee208e8c22ded31354eaa3a44c7ed4df2e3c
db673c4288f4379ce6b31aee8a064e5c54d782af8ee6d10b8fcb6c68b80fd086
3e3b3e7ec70e9d86d9588c81ffe670167d40f111bb37fb41228e978a9515238a
8967724e79948f517a60bfc7b29b116eea1560f5ce40292492a205e7f6750700
c9d26e886a7faac1a9869eba2e4ead800e7920f58ec0802ce504bee08406f389
be89303f8d80849254cde87c7a73f408930a351b4383217feb46a1b0e59608eb
5078694527bf07733cb2775253829b0e227b1fe895e3fc9f1fd934ddc125486b
5f83e0d2167d6e2700bae6e1736b2d24faf37ae7f6592e517863065072a2aa52
c8675f598997e97b87f5be9b7a49b8b84792b776488c572646bda498c016f3ea
956a15acd1fab4bc70f7988a26456298ccc0a2aaa9179b39c8593fde6f489023
b27d9fc4edc252f76f291cc48ec4ee78a6b9f34de85055331e1d90b82b0aca59
5fdd8e71847be4f2b7f328dbb815a3471239532e0f831b42f15657fd2ef30fb4
cdd529942c2aeca5ddb4c89ad58a39c9a279489a133ca8159d14dbbdcd39d7bc
84a795ba40f30380
```

Verified trailer: `ddb4c89ad58a39c9a279489a133ca8159d14dbbdcd39d7bc84a795ba40f30380`.

`SHA256(packet[:-32]) == packet[-32:]` is **True**.

### Cloud exchange frame 28 — type 1, 168 bytes

```text
837000a0200100006e695c5cd2672e8c3966ed3b6b163b533c72fb2c26760aec
bf158b1bbc6756f7cf615e2ded8ceef84f9fdce0f4b7261b87444fa5f56b76b1
220ee13dd0e2dee6cb16518aa9eedbee5b94c5257d2532d4a166e3c364615cc8
a536e3a86095a0616a3d5a893b309859cbd61d73847c1671759e1ba7ed9126b5
312b93cdf85cf42a18b40ac2bb85886a41af09135653cb7f99314995902cff08
d48b73ee19539914
```

Verified trailer: `18b40ac2bb85886a41af09135653cb7f99314995902cff08d48b73ee19539914`.

`SHA256(packet[:-32]) == packet[-32:]` is **True**.

### Cloud exchange frame 30 — type 2, 54 bytes

```text
8370002e20b2a133f9c821a2f6582acd95107b4f9502b920c2846c4ea8188b19
9e26dde664840d7b5027e15b683122d02ad44b275438
```

### First post-exchange type 3 message — frame 31, 150 bytes

```text
8370008e2063488d92c201e5eb8040f730610c8fb525ce400cca9ac75ca9d319
c00aee111c1ab312310977c86f87ee3a7e2999b88d804d1f20ddd847611f3468
390235c78550230c6354306ad469b0b523632f3ce5e5397ab40cc27cb91149dd
b15169f4f8c33eb19527ce69f4a3f4cd53d876e51d97cff842c62317509d581e
46df060157418c6cd0ae2c6e175ec38678e83d346e95
```

### Verified authentication layout versus hypotheses

| Type | Verified structure | Unconfirmed interpretation |
| --- | --- | --- |
| 8 | 6-byte header + `0000` + 384 opaque bytes + SHA-256 over preceding wire bytes | Initial credential/authentication request; `0000` may be a counter |
| 1 | 6-byte header + `0000` + 128 opaque bytes + SHA-256 over preceding wire bytes | Server key-exchange response; contents and derivation unknown |
| 2 | 6-byte header + 16 opaque bytes + 32-byte tail | Encrypted confirmation with digest |

The type 8 and type 1 checksums are **unkeyed SHA-256**, not HMAC or a public-key
signature. They verify packet bytes but do not authenticate the peer by
themselves. Their opaque fields could contain ciphertext or structured
credentials; neither interpretation has been established.

For type 2, header `8370002e20b2` gives type 2 and, under the LAN convention,
11 padding bytes. If its body is AES-CBC plus a 32-byte digest, there is one
16-byte encrypted block containing two counter bytes, three application bytes,
and 11 padding bytes. No plaintext or digest validation has confirmed this.
`SHA256(packet[:-32])` does **not** match its trailing 32 bytes.

### Reproduce handshake extraction and digest checks

```bash
python3 - <<'PYCODE'
import json
messages = []
for line in open('midea-reboot-payloads.tsv'):
    frame, t, src, sport, dst, dport, length, payload = line.rstrip().split('\t')
    if int(frame) not in (26, 28, 30):
        continue
    b = bytes.fromhex(payload.replace(':', ''))
    messages.append(dict(frame=int(frame), relative_seconds=float(t),
                         source=src, destination=dst, length=len(b),
                         type=b[5] & 15, hex=b.hex()))
with open('midea-reboot-handshake.json', 'w') as output:
    json.dump(messages, output, indent=2)
PYCODE

python3 - <<'PYCODE'
import hashlib, json
for item in json.load(open('midea-reboot-handshake.json')):
    packet = bytes.fromhex(item['hex'])
    print('frame', item['frame'], 'type', item['type'], 'bytes', len(packet))
    print('declared size + 8:', int.from_bytes(packet[2:4], 'big') + 8)
    print('wire SHA256 matches:',
          hashlib.sha256(packet[:-32]).digest() == packet[-32:])
PYCODE
```

Expected digest results: frame 26 **True**, frame 28 **True**, frame 30 **False**.

## 7. Discovery broadcast decryption

The first UDP broadcast is frame 20, a 208-byte UDP payload. It starts with
transparent outer frame `837000c8200f0000`, followed by an inner `5a5a` packet.

### Exact first discovery broadcast — frame 20, UDP payload

```text
837000c8200f00005a5a0111b8007a00010000000000000000000000d62d3000
008a0000000000000000018000000000a095a865068d41d1671894ecb05dbf91
f36fc400f249f6dda8db87d9195fdf793fcdb8c18755fbe9d35cda3a842c5bd7
c92c67de56e7a381ae2c3638f03c13bde2e2d942093c4a248a8d76c2a366f406
a85b7af854575bc703088b93e421c1d94bdfb3e16e33d88768cc4c3d0658937d
96fbcce99f70c976413c2f05f60f82e77b4da31005158b744932bc74da7abbf3
af8d46572dc46c9221c26660599d7958
```

The inner header declares **184 bytes**, although 200 bytes remain after
removing the eight-byte outer prefix. The final 16 bytes outside that declared
inner packet remain uninterpreted. Trimming to the declared inner length is
necessary to select the correct encrypted body and MD5 trailer.

Using the published discovery signing constant:

```text
signing_constant = ASCII("xhdiwjnchekd4d512chdjx5d8e4c394D2D7S")
discovery_AES_key = MD5(signing_constant)       # raw 16-byte digest
inner_MD5 = MD5(inner_packet_without_trailer + signing_constant)
plaintext = AES-128-ECB-decrypt(discovery_AES_key, inner_packet[40:-16])
plaintext = PKCS#7-unpad(plaintext)
```

The inner MD5 validates and decryption succeeds. The first attempt incorrectly
used all 200 remaining bytes, producing `bad decrypt`; respecting the declared
184-byte inner length fixed both checks. This is discovery decryption only.

Exact reproducible command (OpenSSL provides AES, Python only uses stdlib):

```bash
python3 - <<'PYCODE'
import hashlib, subprocess
sign = b'xhdiwjnchekd4d512chdjx5d8e4c394D2D7S'
relative_time, payload_hex = open('midea-reboot-broadcasts.tsv').readline().strip().split('\t')
outer = bytes.fromhex(payload_hex.replace(':', ''))
inner = outer[8:]
inner = inner[:int.from_bytes(inner[4:6], 'little')]
assert hashlib.md5(inner[:-16] + sign).digest() == inner[-16:]
result = subprocess.run(
    ['openssl', 'enc', '-d', '-aes-128-ecb', '-K', hashlib.md5(sign).hexdigest()],
    input=inner[40:-16], capture_output=True, check=True)
open('midea-discovery-plaintext.bin', 'wb').write(result.stdout)
print('Device ID:', int.from_bytes(inner[20:26], 'little'))
print('Plaintext hex:', result.stdout.hex())
print('Plaintext:', repr(result.stdout))
PYCODE
```

The resulting 124-byte plaintext contains the IP in reversed byte order
(`85 c8 a8 c0`), TCP port `2c 19 00 00` (6444 little-endian), the serial,
name, and MAC. Exact plaintext:

### Decrypted discovery plaintext — 124 bytes

```text
85c8a8c02c190000303030304536353431323736303030323434363134314130
303339344e3932350d6d696465615f65365f303339340000bf05020000000000
00000000e600170000000000b80bdacea2300590060923060003000000000000
00000000000000000000000000000000000000000000000000000000
```

## 8. Session-key research and bounded candidate checks

The reference **LAN** handshake sends a type 0 token request and receives a
64-byte response body consisting of 32 encrypted bytes and a 32-byte digest:

```text
R = AES-CBC-decrypt(device_key, IV=all_zero, ciphertext_32)
require SHA256(R) == response_digest_32
LAN_session_key = R XOR device_key
```

Subsequent LAN encrypted packets use AES-CBC with zero IV and a trailing digest
of `header + decrypted_padded_body`. This is **not a confirmed description of
the cloud key exchange**: the captured cloud request and response have
384-byte and 128-byte opaque fields, respectively, and use types 8 and 2
that the inspected LAN implementations do not implement.

A bounded offline check tested **64 distinct candidate keys** against both
type 2 frame 30 and type 3 frame 31. Candidates were all aligned 16- and
32-byte slices of the opaque initial request and response, plus two published
constants. No candidate produced a valid SHA-256 under the LAN convention.

This was not an exhaustive key search. It only rejected the tested direct-key
interpretations with that cipher/IV/digest assumption. It did not test every
possible key derivation or establish a cloud AES key size.

Reproduce exactly:

```bash
python3 - <<'PYCODE'
import hashlib, json, subprocess
messages = json.load(open('midea-reboot-handshake.json'))
request, response, confirmation = [bytes.fromhex(m['hex']) for m in messages]
first_data = next(bytes.fromhex(line.rstrip().split('\t')[-1].replace(':', ''))
                  for line in open('midea-reboot-payloads.tsv')
                  if line.split('\t')[0] == '31')
candidates = {}
for name, body in [('request', request[8:-32]), ('response', response[8:-32])]:
    for size in (16, 32):
        for offset in range(0, len(body) - size + 1, 16):
            candidates.setdefault(body[offset:offset + size],
                                  f'{name} block {offset}:{offset + size}')
candidates.setdefault(hashlib.md5(b'xhdiwjnchekd4d512chdjx5d8e4c394D2D7S').digest(),
                      'discovery')
candidates.setdefault(bytes.fromhex(
    'c8aa6c57402cac8b5674db84acc89be82c704362da72b5ff21544b483b50d39c'),
    'app internal')
matches = []
for key, name in candidates.items():
    for label, packet in [('confirmation', confirmation), ('first type 3', first_data)]:
        result = subprocess.run(
            ['openssl', 'enc', '-d', f'-aes-{len(key)*8}-cbc', '-K', key.hex(),
             '-iv', '00' * 16, '-nopad'],
            input=packet[6:-32], capture_output=True)
        if result.returncode == 0 and hashlib.sha256(
                packet[:6] + result.stdout).digest() == packet[-32:]:
            matches.append((name, label))
print('Candidate keys:', len(candidates))
print('Matches:', matches)
PYCODE
```

Expected output: `Candidate keys: 64`, `Matches: []`.

### Brute force / rainbow-table feasibility

There is no evidence that this session key comes from a weak password or a
small predictable key set. Exhaustive search of a uniformly generated AES key
is impractical. For illustration, a 128-bit key has approximately
`3.4 × 10^38` possibilities; at an assumed `10^12` trials/second, average search
would take approximately `5.4 × 10^18` years. Rainbow tables exchange storage
for computation and do not make that full key space feasible.

Capturing a handshake is useful for reverse engineering, but does not alone
supply any secret required by its key derivation. The successful discovery
constant must not be confused with a recovered cloud session key.

## 9. Exact selected DNS payloads

These are UDP application payloads, without UDP/IP/Ethernet headers.

### DNS query — frame 19

```text
ae4d01000001000000000000096d6f64756c652d75730a6d736d6172746c6966
65036e65740000010001
```

### DNS response — frame 22

```text
ae4d81800001000300000000096d6f64756c652d75730a6d736d6172746c6966
65036e65740000010001c00c000500010000012c002c11616636306530626139
383734333734653214617773676c6f62616c616363656c657261746f7203636f
6d00c03600010001000000c0000423478898c03600010001000000c0000434df
2fd7
```

## 10. Artifacts

| File | Purpose |
| --- | --- |
| `capture_tzsp.py` | Standard-library UDP TZSP receiver and Ethernet PCAP writer |
| `midea-inner.pcap` | 180-second established-session capture; 212 packets |
| `midea-reboot.pcap` | 120-second reboot capture; 283 packets |
| `midea-payloads.tsv` | All initial-capture TCP payloads, timestamp/source/length/hex |
| `midea-reboot-payloads.tsv` | All reboot TCP payloads, frame/time/endpoints/length/hex |
| `midea-reboot-broadcasts.tsv` | All 44 reboot UDP port-15000 payloads |
| `midea-reboot-handshake.json` | Exact frames 26, 28, and 30 plus metadata |
| `midea-reboot-selected-udp.json` | Exact UDP bodies of frames 19, 20, and 22 |
| `midea-discovery-plaintext.bin` | First decrypted discovery plaintext, 124 bytes |
| `midea-ack-times.txt` | Initial-capture Wireshark ACK timing samples |
| `cloud-auth-findings.md` | Earlier investigation notes |
| `README.md` | Consolidated procedure, evidence, and limitations |

Recreate selected UDP JSON if needed:

```bash
python3 - <<'PYCODE'
import json, subprocess
fields = subprocess.check_output([
    'tshark', '-n', '-r', 'midea-reboot.pcap',
    '-Y', 'frame.number == 19 || frame.number == 20 || frame.number == 22',
    '-T', 'fields', '-e', 'frame.number', '-e', 'udp.payload'], text=True)
items = {frame: payload.replace(':', '')
         for frame, payload in (line.split('\t') for line in fields.splitlines())}
with open('midea-reboot-selected-udp.json', 'w') as output:
    json.dump(items, output, indent=2)
PYCODE
```

## 11. Remaining unknowns and next evidence

Confirmed: device identity, observed cloud hostname/IPs, reconnect sequence,
outer frame lengths/types, two wire SHA-256 checksums, and first discovery
packet decryption.

Still unknown:

- Meanings and internal fields of the 384-byte type 8 request and 128-byte
  type 1 response.
- Cloud root credential, cipher/key size, IV, and exact session-key derivation.
- Actual type 2 plaintext and application type 3 plaintext.
- Wi-Fi module model, chipset, firmware version, and firmware image.
- Whether this appliance's LAN authentication can be completed with credentials
  obtainable through its configured cloud account.

The E6 boiler implementation provides application-message parsing and control
code, but is not a specification for the captured cloud handshake. No live
LAN probe, account login, firmware extraction, or appliance setting change
was performed. The owner configured the router and rebooted the appliance.

The most direct next evidence is the Wi-Fi module model/firmware version from
the app's device information, or a matching firmware image containing the
cloud authentication parser and cryptographic calls. A second reboot capture
would allow comparison of stable versus changing handshake bytes; the public
researcher's observation of a stable first cloud message on another appliance
has **not** been reproduced on this boiler.

## 12. Sources inspected

The findings above come primarily from the local captures. External references
provide framing conventions, discovery constants, LAN key derivation, appliance
identity, and related research; none inspected explains this exact cloud
session-key derivation.

- [MikroTik Packet Sniffer documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/8323088/Packet%2BSniffer): TZSP streaming.
- [Midea L1PB20-C28WM product page](https://www.midea.com/ge-en/water-heaters/gas-boiler/gas-boiler-l1pb18-c28wm.l1pb20-c28wm): Wi-Fi gas boiler identity.
- [midea-msmart LAN implementation](https://github.com/mill1000/midea-msmart/blob/master/msmart/lan.py): V3 framing, CBC/digest convention, LAN key derivation.
- [midea-beautiful-air crypto implementation](https://github.com/nbogojevic/midea-beautiful-air/blob/main/midea_beautiful/crypto.py): discovery AES/MD5 and LAN session handling.
- [midea-beautiful-air constants](https://github.com/nbogojevic/midea-beautiful-air/blob/main/midea_beautiful/midea.py): discovery signing constant and app-internal key used in bounded checks.
- [midea-local E6 implementation](https://github.com/midea-lan/midea-local/tree/main/midealocal/devices/e6): boiler application protocol.
- [Midea PortaSplit reverse-engineering notes](https://maxammann.org/posts/2026/05/notes-midea-portasplit/): another appliance's `8370` cloud connection on port 28443; does not recover the cloud key derivation.
- [NIST AES specification](https://csrc.nist.gov/pubs/fips/197/final): AES key sizes.

Source URLs track live branches/pages; their contents can change. Exact local
capture payloads and evidence are preserved in this workspace.

## 13. Recording proxy and local HTTP/HTTPS server

Prepared after the initial investigation to inspect selected traffic while
preserving access to the real cloud. Files:

- `local_server.py`: standard-library recording TCP proxy and HTTP/HTTPS status endpoints.
- `certs/openssl.cnf`: certificate generation configuration.
- `certs/server.crt`: generated self-signed server certificate.
- `certs/server.key`: generated RSA private key, filesystem mode 600, ignored by Git.
- `router-redirect.rsc`: scoped RouterOS NAT commands, **not applied by the agent**.
- `proxy-logs/`: JSONL events and exact per-connection directional byte streams, ignored by Git.

Topology:

```text
Boiler → original cloud IP:28443
       → MikroTik destination NAT → Mac 192.168.200.164:28443
       → recording TCP proxy → real cloud 35.71.136.152:28443
```

The proxy forwards raw bytes unchanged in both directions, including the
authentication exchange. It logs complete `8370` frames after reassembling
TCP chunks, plus raw directional streams. It does not decrypt, replay, or
forge authentication messages. Port 28443 is raw TCP, not an HTTPS endpoint.

The separate HTTP (8080) and HTTPS (8443) endpoints return JSON status.
Their certificate is not used on the proxied cloud connection and does not
make the boiler trust a substituted TLS server. No port-80/443 appliance
redirect or DNS override is configured.

### Certificate generation and verification

Executed once:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
  -config certs/openssl.cnf -keyout certs/server.key -out certs/server.crt
chmod 600 certs/server.key
openssl verify -CAfile certs/server.crt -verify_ip 192.168.200.164 certs/server.crt
openssl x509 -in certs/server.crt -noout -subject -dates -ext subjectAltName
```

Verification returned `certs/server.crt: OK`. Certificate validity:
2026-10-11 10:31:29 UTC through 2027-10-11 10:31:29 UTC. SANs:
`module-us.msmartlife.net`, `localhost`, `192.168.200.164`, `127.0.0.1`.
Regenerating with the command above overwrites both existing certificate files.

### Start the server before changing router rules

The sandbox denied binding TCP 28443, just as it denied the UDP receiver.
The server is **not running** as a result of the agent's startup attempt.
Run in the Mac terminal and leave it running:

```bash
cd /Users/user/Projects/Midea
python3 local_server.py
```

Wait for an event with `"event": "listening"`. In another Mac terminal:

```bash
curl http://192.168.200.164:8080/
curl --cacert certs/server.crt https://192.168.200.164:8443/
```

These status checks exercise HTTP/HTTPS, not a real appliance session. Allow
the listener through the Mac firewall if needed. If the server cannot connect
to the upstream, the proxied session closes and an error is logged; it does
not silently bypass itself. The fixed upstream is an IP observed in the
capture. The other returned cloud IP can be selected explicitly with:

```bash
python3 local_server.py --upstream 52.223.47.215
```

### Redirect only the boiler's cloud TCP port

Execute these on the MikroTik **after** the listener is ready. The source-NAT
rule ensures replies traverse the router, because the Mac and boiler share
a subnet. It causes the proxy to see the router's address as its client.
The source-address restriction keeps the Mac's upstream connection outside
the redirect, avoiding a proxy loop.

```routeros
/ip firewall nat add chain=srcnat src-address=192.168.200.133 dst-address=192.168.200.164 protocol=tcp dst-port=28443 action=src-nat to-addresses=192.168.200.1 place-before=0 comment="midea-research-proxy-srcnat"
/ip firewall nat add chain=dstnat src-address=192.168.200.133 protocol=tcp dst-port=28443 dst-address=!192.168.200.164 action=dst-nat to-addresses=192.168.200.164 to-ports=28443 place-before=0 comment="midea-research-proxy-dstnat"
/ip firewall nat print stats where comment~"midea-research-proxy"
```

Apply the rules once; repeating the `add` commands creates duplicates.
The same commands are in `router-redirect.rsc`. Existing connections retain
their NAT mappings. Reconnect/reboot the boiler to create a new session,
without clearing the router's entire connection table. Existing forward
firewall rules must permit the routed appliance-to-Mac connection; the
prepared commands do not change the forward filter.

### Read recorded traffic

```bash
tail -f proxy-logs/events.jsonl
```

Each session writes `<session>-device-to-cloud.bin` and
`<session>-cloud-to-device.bin`. JSONL frame events include full frame hex,
type, header, direction, and UTC time. Chunk events contain stream offsets
and lengths. These are TCP stream recordings, not PCAP files. A client
reconnect creates a new session and new files. Status endpoint data shows
active/total connections. Logs contain captured device authentication bytes.

### Restore direct cloud access

First remove only these tagged rules on the MikroTik:

```routeros
/ip firewall nat remove [find comment="midea-research-proxy-dstnat"]
/ip firewall nat remove [find comment="midea-research-proxy-srcnat"]
```

Then reconnect/reboot the boiler so the old proxied NAT mapping is replaced
by a direct connection. Keep the proxy running until the old session has
closed; stop it with Ctrl-C afterward.

### Validation completed

Reproduce the bidirectional relay checks without binding network sockets:

```bash
python3 verify_local_server.py
```

- Recorded handshake frames reassemble correctly when split into arbitrary
  TCP chunks or coalesced into one chunk.
- The generated certificate and key load into Python's TLS server context.
- In-memory stream checks using captured type 8/1/2 packets verified unchanged
  forwarding in both directions, exact raw log contents, frame events,
  half-close behavior, and connection cleanup.
- Live listeners, HTTP/HTTPS requests, router NAT, and appliance/cloud traffic
  through the proxy remain **unverified** because sandbox socket access was denied.

NAT behavior reference: [MikroTik NAT documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/3211299/NAT).

## 14. Artifact fingerprints

SHA-256 values recorded after README verification:

| File | SHA-256 |
| --- | --- |
| `capture_tzsp.py` | `3bb4bba4a1ad85a198e64faa992fdf39fa7c79a2cc050010cf9ab08935343d8b` |
| `midea-inner.pcap` | `dfc306845c2de2a3bceca2bf8e8c167352283da387d6290156e6eadf2b53be8c` |
| `midea-reboot.pcap` | `4dd04cc6b570391f3ea34ee6c027a9bf6890afc97359079d922d4c428e414920` |
| `midea-reboot-handshake.json` | `a5c67d6868b24c4f7e3a8355413b07ff64a45fb1d3196f031f088b8ea8c65d6a` |
| `midea-discovery-plaintext.bin` | `9ad02bc8dca2d3135938dbbbfcd3bb25cf2c75f4e1d0c402209c7d1405d0441d` |

## 15. Redirect troubleshooting observations

After applying redirect commands, the owner's NAT statistics showed only
`midea-research-proxy-dstnat`, with 528 bytes / 12 packets. No tagged source-NAT
rule appeared. Local `proxy-logs/events.jsonl` contained two `listening` events
at 10:36:12.936792 and 10:37:55.805779 UTC, but no `connect` events. The earlier
terminal invocation was reported aborted; later log entries show that a server
was started at least twice. Local `lsof` checks showed no listeners at the
time of troubleshooting, although sandbox process visibility is limited.

Destination-NAT counters alone do not prove an established TCP connection;
12 small packets may be connection attempts. The missing source NAT prevents
the required symmetric return path on this shared subnet. The original
source-NAT command included an unnecessary `connection-nat-state=dstnat`
matcher, which may have been rejected by the router. That matcher was removed
from `router-redirect.rsc` and the command examples above. RouterOS command
errors and detailed rules would be needed to establish why the rule is absent.

With the destination rule already installed, add only the missing source rule
from section 13, start the proxy in a persistent Mac terminal, verify the local
HTTP status endpoint, then reconnect the appliance to establish new NAT
mappings. Do not add another destination rule.

Diagnostic commands:

```bash
curl --max-time 3 http://192.168.200.164:8080/
lsof -nP -iTCP:28443 -sTCP:LISTEN
tail -f proxy-logs/events.jsonl
# If necessary, run on the Mac outside the agent sandbox:
sudo tcpdump -i en0 -nn -s 0 'tcp port 28443'
```

```routeros
/ip firewall nat print detail where comment~"midea-research-proxy"
/ip firewall nat print stats where comment~"midea-research-proxy"
```

On the Mac-facing leg, the incoming TCP source should be `192.168.200.1`
when the source-NAT rule applies. SYNs without a completed handshake warrant
checking the Mac listener/firewall and router forward-filter counters.

## 16. Successful proxy capture and cross-session comparison

The repaired redirect reached the proxy. A snapshot of `events.jsonl` was
saved in `proxy-analysis-snapshot.json`; its three complete handshakes are
saved in `proxy-handshakes.json`. These are offline snapshots: the live logs
may continue growing. The proxy was not stopped by the investigator.

At the snapshot there were 128 complete frame events across three sessions,
including three device type 8 messages, three server type 1 messages, and
three device type 2 messages. Every handshake was followed by type 3 traffic
in both directions, consistent with successful cloud authentication. This
does not by itself verify every function exposed by the vendor app.

| Session (UTC start in filename) | Device frames / bytes | Cloud frames / bytes | Total frames |
| --- | --- | --- | --- |
| `20261011T104256577719Z-1` | 23 / 3564 | 16 / 2130 | 39 |
| `20261011T104507129696Z-1` | 16 / 2386 | 14 / 1894 | 30 |
| `20261011T104526796986Z-2` | 40 / 6290 | 19 / 2500 | 59 |

The six raw binary stream files exactly matched concatenated frame events
for their respective sessions and directions when checked, with zero
leftover/unlogged bytes. Incoming peers were `192.168.200.1`, confirming the
expected source-NAT address. Total recorded application bytes: 18,764.

The first session closed after device EOF. The second received cloud EOF
and then a connection-reset error around 10:45:31 UTC; a replacement session
had already started at 10:45:26 UTC. This is consistent with reconnect/reboot
cleanup, though the physical reboot timestamps were not recorded. The third
session has no closure event in the snapshot, and its last recorded frame
was at 10:46:52.331011 UTC.

### New evidence: a stable 128-byte request field

Compare the earlier PCAP handshake with the three proxy handshakes:

```text
Type 8 request, 424 bytes:
  [0:6]     6-byte header 837001a02008
  [6:8]     0000 (presumed counter)
  [8:264]   256-byte block, different in all four captured handshakes
  [264:392] 128-byte block, identical in all four captured handshakes
  [392:424] SHA256(packet[0:392]), validated for every request

Type 1 response, 168 bytes:
  [0:6]     6-byte header 837000a02001
  [6:8]     0000 (presumed counter)
  [8:136]   128-byte block, different in all four captured handshakes
  [136:168] SHA256(packet[0:136]), validated for every response

Type 2 message, 54 bytes:
  [0:6]     6-byte header 8370002e20b2
  [6:22]    16-byte opaque block
  [22:54]   32-byte tail; not SHA256 of preceding wire bytes
```

All four complete type 8 requests differ, correcting any assumption that this
boiler sends an entirely static initial request. The exact 128-byte constant
region is now established. Its purpose remains unknown: calling it a token,
public key, signature, or device credential would be speculative. The changing
256-byte and 128-byte sizes alone do not establish RSA or any other cipher.
No session key has been derived and no cloud plaintext has been recovered.

Stable request field SHA-256: `81a0771cc761233635d331ff781602b4401a831e6de9e2577c3f6e8ad993f0da`.

Reproduce the comparison:

```bash
python3 - <<'PYCODE'
import hashlib, json
old = json.load(open('midea-reboot-handshake.json'))
new = json.load(open('proxy-handshakes.json'))
requests = [bytes.fromhex(next(r['hex'] for r in old if r['type'] == 8))]
requests += [bytes.fromhex(r['hex']) for r in new if r['type'] == 8]
assert len(requests) == 4
assert len({r[8:264] for r in requests}) == 4
assert len({r[264:392] for r in requests}) == 1
for record in new:
    packet = bytes.fromhex(record['hex'])
    print(record['session'], record['direction'], record['type'], len(packet),
          hashlib.sha256(packet[:-32]).digest() == packet[-32:])
print('Stable request block:', requests[0][264:392].hex())
PYCODE
```

### Exact proxy handshake payloads

Hex below is complete application-frame data. Concatenate wrapped lines to
recover each frame. For all subsequent application frames, see the full
`proxy-analysis-snapshot.json` and the original directional `.bin` files.

#### 20261011T104256577719Z-1 — 2026-10-11T10:42:56.756916+00:00, device-to-cloud, type 8, 424 bytes

```text
837001a0200800005d7394810b6d98b68c1bdfddcfbae23b421e55df049c553d
003e6446c8c8737d056757ce2d90fd80b9ad27cd961437e562d00684bb6eaa98
dec1224fc298458c04900de2a25e6ebbf658e7f21f5c7a6c7e5c2c2adc4c38fc
1676dcb5ed2482916567837ec60eb03dab36dcd6bab0ce69bdce61198ab7b432
314e46fa054d6bc33473f4279253b716112820a7e32dd1e11d1a6864fbc526f1
41c63fa9e940c51a5c45a87d9df3e6c78cefb4df0cf325d2f0bd486684e2c600
c850785093a6d2ee4133f6521cec4af13300090ae48cedf030463c211791d218
3c93726ca4ab4e6c1746d871c3e55b13d852c53ca93e7a7ca4baa3e146217b9f
f2909e5f457e33d387f5be9b7a49b8b84792b776488c572646bda498c016f3ea
956a15acd1fab4bc70f7988a26456298ccc0a2aaa9179b39c8593fde6f489023
b27d9fc4edc252f76f291cc48ec4ee78a6b9f34de85055331e1d90b82b0aca59
5fdd8e71847be4f2b7f328dbb815a3471239532e0f831b42f15657fd2ef30fb4
cdd529942c2aeca5e18db5327b01b778721a208534663c0941c3766b6c95dff5
74192c4e49186209
```

#### 20261011T104256577719Z-1 — 2026-10-11T10:42:56.977388+00:00, cloud-to-device, type 1, 168 bytes

```text
837000a02001000053ce7feefc39d54c696e8e124ee3148b89c0310149de7618
f2567d651b6b4a7de5a81f6e3f1296898c9f2ee75bab985d44c92127c3401fa1
2fb5833d5216d30a43bae5d36689183f9936c5b662a5dc0cb4ca2cec701d36c0
f72e99f0103d30bdd1ecafbc75ba728693474abd91149bad4c2f0af83f18fa62
d5d60a99b1dad459e337ab93013faf108d66e9fa2811687707b72d3c5beceb55
531e110969cbb451
```

#### 20261011T104256577719Z-1 — 2026-10-11T10:42:57.517659+00:00, device-to-cloud, type 2, 54 bytes

```text
8370002e20b2aed73b0323c5cc7773d6fd423edfb5216afa2767f8108a8427ac
8b733be2bfdd5bd8d26230fc8ca414467fda8cb9dd65
```

#### 20261011T104507129696Z-1 — 2026-10-11T10:45:07.281790+00:00, device-to-cloud, type 8, 424 bytes

```text
837001a0200800008440daa8588524421284eb51e2d967ac7e55f41e7ac34a0a
3ff075b3e5266823a070702740866db194d0a8979ceee543632c22527c659fd8
1dab8c3637899e943583d7e65ec0f2be12c4199339a5e1eb302d99707b39766a
ccda4b9ae1eb68d9ebf1da591d2dd121b52c49629dbab3ba131fd63875007951
6ac5576ca79ff0a80946a4ce71e97e9a17db23f15505ab5bbc129102b290235e
df121de084354b29fd48032b40eae68f955ae7e47fbc5ca3fea91f13acc4a520
0447e0c380f3cc27026d0345fd5ed6377e823f75849acf04ffaf722224f46d2b
e0d1e6b825922016a45e5068ce6db21ede5def2544d57278fb30b126215c5814
dbfc505533625dac87f5be9b7a49b8b84792b776488c572646bda498c016f3ea
956a15acd1fab4bc70f7988a26456298ccc0a2aaa9179b39c8593fde6f489023
b27d9fc4edc252f76f291cc48ec4ee78a6b9f34de85055331e1d90b82b0aca59
5fdd8e71847be4f2b7f328dbb815a3471239532e0f831b42f15657fd2ef30fb4
cdd529942c2aeca55b3c5a7560e92b151d34b6d76cba9ad354232fd5dde9de6e
babe64f979fb180f
```

#### 20261011T104507129696Z-1 — 2026-10-11T10:45:07.500113+00:00, cloud-to-device, type 1, 168 bytes

```text
837000a0200100001d1685a3fb03b0718612487e6cb685003e6254dd941b7c7d
69f5e9c382d5d62fe5d8e0eb658bab40066e0a822d5eb6a8a33262962e2faff1
c728dd65836b645494c265a6b93f52dae5db0a51b11e01000e9edbb76bb24c12
925bc835ced8e6511e8d292a06466bf434b6bf6420ec7cc7677da72d60d9f499
d718277b437f705a89aba06f8183dcfca01874c911d7f5ef5b287d0c4d8e7c01
b2ea49d690d4f3af
```

#### 20261011T104507129696Z-1 — 2026-10-11T10:45:08.168885+00:00, device-to-cloud, type 2, 54 bytes

```text
8370002e20b2521e5f5e394ab70a67be39729834b0324978824c83b524342042
53501f5375e60213f2c3ea3c6f9fec4eec4acd0da913
```

#### 20261011T104526796986Z-2 — 2026-10-11T10:45:26.945713+00:00, device-to-cloud, type 8, 424 bytes

```text
837001a0200800009725af4750fa86a72c449270a1ecfd257c0d2b21f44f6d94
79a8be104165f009d0cf6b18c60495bfa69e2b909f6c4d8b4ff985acd1195ac1
9b6af0027b5cca7b0629c52b08abd791d89117ce5168316a629302e1d4418476
eef2e846977323de11f87db6888395c01770b7795968e0c545dc839f12989874
3e4a2914d108a2e76377e5598b6edda0f1dd0d87fba5d1f34189ce1ed8fac7d3
8cdda748fe48a188f2963290b0d915c4d534f7319201b30b8de0a0a89da05db9
e040f4410cc7cf3d9b83cf9d0fb0e3154b7c6f736d48a7da5f472cf50ac2356f
8919220a831ecca2d6e0b9bb24bc046611669a10b7fd3651d8d4fd51f407c9e9
edfb7df13e139e9587f5be9b7a49b8b84792b776488c572646bda498c016f3ea
956a15acd1fab4bc70f7988a26456298ccc0a2aaa9179b39c8593fde6f489023
b27d9fc4edc252f76f291cc48ec4ee78a6b9f34de85055331e1d90b82b0aca59
5fdd8e71847be4f2b7f328dbb815a3471239532e0f831b42f15657fd2ef30fb4
cdd529942c2aeca56dea9c37b037107c9237df3b9ef83aa3b297ed12c861965b
4d644762a3d8ecf8
```

#### 20261011T104526796986Z-2 — 2026-10-11T10:45:27.164701+00:00, cloud-to-device, type 1, 168 bytes

```text
837000a02001000079225e90215cafa0ce4056d450855860b8c514757080ce90
45991c06bfcdd8d4d4d03d2cc8dd24d897aee6cfa757015800558c740ceca1f8
47f82e70a1024ce3ec4abe3971cc9e09cc4e9470cecaec5372b19340db45533b
4b78bbc77c3d88708e9528a2de1e5f3d63fe2e6c7679f76c21bd451a7b05314d
ae1b2187a9c3ace65debd302e136616b18a62f24e1ef42f8286ed2c4ce36b13b
829d21fca59302d8
```

#### 20261011T104526796986Z-2 — 2026-10-11T10:45:27.706134+00:00, device-to-cloud, type 2, 54 bytes

```text
8370002e20b22cdf9cf1e73fe1d5b241393c19ef20750fba9b2d6194fa17837e
a1c16707efe9c6e730be8a9d184651fcdffcdff1e689
```

## 17. Obtain and verify the boiler LAN token/key (prepared, awaiting live execution)

The owner authorized retrieval and verification of LAN credentials for device
`151732607790550` (`192.168.200.133`, TCP `6444`). No valid pair has been
obtained yet. The research sandbox could not resolve PyPI, so installing
`midea-local` failed before contacting the cloud or boiler. Its failed commands:

```bash
env UV_CACHE_DIR=.uv-cache uv venv .venv --python /opt/homebrew/bin/python3
env UV_CACHE_DIR=.uv-cache uv pip install --python .venv/bin/python midea-local
```

Prepared `run_lan_key.sh` and `obtain_lan_key.py`. Run from the Mac terminal:

```bash
cd /Users/user/Projects/Midea
bash run_lan_key.sh
```

The launcher creates `.lan-venv` with installed Python 3.12 (avoiding dependency
wheel availability concerns with Python 3.15), then runs:

```bash
python3.12 -m venv .lan-venv
.lan-venv/bin/python -m pip install midea-local
.lan-venv/bin/python obtain_lan_key.py
```

The script first checks TCP reachability, then revalidates a cached pair if
present. Otherwise it uses midea-local's preset-account cloud flow to request
candidates for this exact device ID and includes the library's published default
candidates. These are finite candidate credentials, not brute force. If none
work, retry with the actual cloud used by the owner's app, for example:

```bash
bash run_lan_key.sh --cloud SmartHome
# Or, if paired through NetHome Plus:
bash run_lan_key.sh --cloud 'NetHome Plus'
```

Account and password are requested interactively; password entry is hidden.
They are not persisted by this script or passed as process arguments.
The cloud name must match a supported backend in the installed package. A failed
cloud lookup reports the exception class, without dumping potentially sensitive
response contents. The package version used is recorded with a successful
handshake. The library APIs can change; failures require inspecting the installed
version. The first live run remains pending.

Verification protocol, implemented directly to avoid depending on E6 status
parser support:

1. Open a fresh TCP connection to `192.168.200.133:6444`.
2. Send `83 70 || BE16(len(token)) || 20 00 || 00 00 || token`.
   For a 64-byte token the prefix is exactly `8370004020000000`.
3. Read the complete response, supporting fragmented TCP reads. Require
   `837000402001` (64-byte payload plus 2-byte counter; 72 bytes total).
4. Let `K` be the 32-byte candidate LAN key; decrypt response bytes `[8:40]`
   with AES-256-CBC, zero IV, no padding removal, yielding 32-byte `R`.
5. Require `SHA256(R) == response[40:72]`. A mismatch is a failed candidate.
6. Derive this connection's session key as `R XOR K` and close the connection.

Only after successful digest verification are the credentials written to
`lan-secrets/credentials.json`. Exact request/response hex, decrypted challenge,
connection-specific session key, timestamp and package version are saved in
`lan-secrets/handshake.json`. Directory mode is 700 and files mode 600; writes
use private temporary files followed by atomic replacement. Both are excluded
from Git. Actual payloads are pending a live successful run; do not invent them
or copy credentials into this README. The session key ends with this closed
connection; future connections must derive fresh keys. Authentication does not
prove that E6 status decoding works, nor that the same key decrypts cloud traffic.

This operation sends a reachability connection and LAN authentication requests;
it sends no appliance setting commands. Existing cloud forwarding on port 28443
is unaffected, and the cloud proxy should remain running while the router
redirect remains enabled.

Offline verification passed: shell/Python syntax, fragmented response assembly,
AES-256-CBC verification using OpenSSL with synthetic data, XOR key derivation,
rejection of a modified digest, and rejection of a truncated response. The tests
substituted the network socket and dependency imports; they do not establish
real appliance authentication or working cloud retrieval.

Implementation references inspected:
[midea-local cloud credential retrieval](https://github.com/midea-lan/midea-local/blob/main/midealocal/cli.py),
[LAN authentication](https://github.com/midea-lan/midea-local/blob/main/midealocal/device.py),
[LAN cryptography](https://github.com/midea-lan/midea-local/blob/main/midealocal/security.py).

### First LAN runner result

The user-triggered shell run installed `midea-local==12.2.0` and its dependencies
successfully, then exited 2 at the TCP reachability check. It never reached cloud
credential retrieval or LAN authentication. The original message suppressed the
OS error detail, so this alone did not establish that the boiler port was closed.
A subsequent connection probe in the research environment returned
`PermissionError: [Errno 1] Operation not permitted`, showing a local execution
restriction for that probe. The runner now prints errno and the OS description,
and suggests external macOS Terminal execution for permission-denied errors.
The user's first failure remains unclassified until rerun with this diagnostic;
it must not be described as a refused connection or a boiler fault.

Run in the macOS Terminal application outside Codex:

```bash
cd /Users/user/Projects/Midea
bash run_lan_key.sh
```

Package cache deserialization warnings occurred during installation; installation
still completed, and those warnings do not explain the subsequent socket failure.

### External terminal TCP access and preset-account result

The owner confirmed that `nc -vz -G 5 192.168.200.133 6444` succeeds and ping
succeeds, while non-root Python returns errno 65. `sudo bash run_lan_key.sh`
gets past the connection check. This establishes TCP reachability from the Mac
and a process/privilege-dependent failure for Python; it does not prove which
macOS permission or network filter caused it. The service name `sge_qmaster`
printed by nc is merely its port-name lookup, not identification of the boiler
service.

The preset NetHome Plus login proceeded to `/v1/iot/secure/getToken`, which
returned code `9999` (`system error`) for both requested UDP-ID encodings after
retries. The sole remaining fallback candidate failed with ValueError; no
verified pair was saved. This is not evidence of an incorrect owner's password:
the owner's credentials were not used in this attempt.

The owner identified the actual paired app as **SmartHome**. Next command, using
that cloud and interactive credentials rather than the NetHome Plus preset:

```bash
cd /Users/user/Projects/Midea
sudo bash run_lan_key.sh --cloud SmartHome
```

Enter the account used to pair this boiler. The account password prompt is
hidden; it is distinct from sudo's password prompt. The installed 12.2.0 backend
supports `SmartHome` and its API proxy at
`https://mp-prod.appsmb.com/mas/v5/app/proxy?alias=`. The runner now reports the
number of matching cloud candidates, and safe verification failure reasons
(length/header/digest) instead of only `ValueError`. Retrieval and successful
verification remain pending.

### Successful SmartHome credential retrieval and LAN verification

The owner ran the following in an external macOS terminal:

```bash
sudo bash run_lan_key.sh --cloud SmartHome
```

The runner reported two matching cloud credential candidates for appliance ID
`151732607790550`. The first candidate passed the live LAN handshake against
`192.168.200.133:6444`, including successful AES-CBC challenge decryption and
SHA-256 digest verification. The runner returned:

```text
Cloud returned 2 matching credential candidate(s).
Checking cloud candidate 1 against 192.168.200.133:6444
VERIFIED: decrypted handshake challenge matches its SHA-256 digest.
Credentials: lan-secrets/credentials.json (mode 600)
Exact handshake and derived session key: lan-secrets/handshake.json (mode 600)
```

LAN token/key retrieval and verification are now complete according to the live
runner output supplied by the owner. The exact secret values and wire payloads
are stored in those private files, not reproduced in this README. As the command
ran with sudo, a subsequent attempt to independently read and revalidate the
saved files in the research environment was denied by file permissions. The
live verification result is established by the supplied runner output; a second
independent saved-file check has not been completed.

The derived session key belongs to the authentication connection that the runner
closed. The persistent LAN token/key can authenticate a new LAN connection and
derive a fresh session key. Successful LAN authentication does not establish
that the cloud type-8 handshake uses the LAN key or that E6 boiler status parsing
works. The next payload investigation can use a fresh authenticated LAN session
and read-only status queries, preserving their encrypted and decrypted bytes.


## 18. Fresh read-only LAN status capture (prepared; live run pending)

`capture_lan_status.py` uses the already verified token/key from
`lan-secrets/credentials.json`. It makes no cloud calls. It opens a fresh TCP
connection to `192.168.200.133:6444`, verifies its handshake and derives a new
session key, then sends one appliance protocol query and three E6 status queries
(default; `--samples` permits 1–5). Only exact library classes
`MessageQueryAppliance` and E6 `MessageQuery`, with message types A0 and 03,
are allowed. Type 02 setting commands are never sent.

Run in the external macOS terminal (Python required sudo in this environment):

```bash
cd /Users/user/Projects/Midea
sudo .lan-venv/bin/python capture_lan_status.py
sudo chown -R "$(id -u):$(id -g)" lan-captures
```

The second command gives the project owner access to review the capture, while
retaining private file modes. It does not change ownership of credentials.
No redirect changes are needed; leave the existing cloud proxy running.

Exact initial appliance query, protocol version zero:

```text
aa1de6000000000000a0000000000000000000000000000000000000005d
```

Exact E6 status query for protocol version zero:

```text
aa28e600000000000003010100000000000000000000000000000000000000000000000000000000ed
```

If the appliance protocol query responds successfully, its protocol version is
used to serialize subsequent status queries; otherwise the library default zero
is used. Each query waits up to eight seconds for a matching response, with two
seconds between queries. This is a bounded sample, not continuous polling.

Outputs are in `lan-captures/<UTC timestamp>/`: `capture.json` with timestamps,
query results, exact wire/inner/appliance/body hex, integrity results and parsed
fields; individual numbered tx/rx `.bin` files; and `session-secret.json` with
this connection's session key. The authenticated request includes the LAN token,
so the entire capture is private and excluded from Git. The connection closes
when capture ends. Any incomplete frame bytes are preserved in the report.

Inbound processing validates the V3 SHA-256 signature, inner 5a5a length and MD5
signature, AES-ECB padding, AA message length and checksum, and E6 device type.
Unexpected frames and decoding failures remain in the capture. E6 fields are
parsed solely from actual decrypted messages, never from device defaults. Field
meanings are the installed midea-local mapping and need comparison with the
boiler display/app. Read-only query success does not validate cloud decryption.

Offline checks passed against installed midea-local 12.2.0: allowed query
serialization, inner packet encryption/decryption and checksums, synthetic E6
status parsing, corrupted inner signature rejection, encrypted V3 round trip,
and fragmented/concatenated TCP frame assembly. No live status capture has yet
been run by the research environment, which cannot read the root-owned
credentials or open the LAN socket. Exact live response payloads remain pending.


## 19. Successful LAN status capture and comparison with cloud snapshot

The owner ran the section-18 capture and changed ownership of `lan-captures`
back to their user. The capture directory is
`lan-captures/20261011T111010805399Z`; timestamps span
2026-10-11 11:10:10.805803–11:10:17.810136 UTC. The handshake succeeded. All
four sent queries received matching replies. Four decoded status messages means
**three query replies (AA type 03) plus one unsolicited notification (AA type
04)**, not four sent status queries. A separate AA type A0 reply reports message
protocol version zero.

Offline inspection independently re-decrypted all five encrypted incoming LAN
frames using the saved session key and rechecked V3 SHA-256, inner MD5, AA
checksum and length. All passed; saved plaintext agrees byte-for-byte with the
new decryption. This validates the captured responses rather than relying only
on the terminal output. Handshake credential files remain private/root-owned.

All four status messages decode to the same fields using midea-local's E6 mapping:
main power on, heating enabled and working, hot-water/bathing working false;
heating target 40°C, hot-water target 41°C; heating outlet 36°C and hot-water
outlet 36°C; heating mode normal; both cold-water flags false; heating limits
30–80°C and hot-water limits 35–60°C. These are interpreted protocol values;
compare with the display/app before treating every field meaning as verified.
`parser_list: []` is parser bookkeeping, not a measured boiler property.

Exact plaintext protocol response (AA type A0):

```text
aa2ae6000000000000a000e617000000000000000000000000000000000000000000000000000000000053
```

Exact plaintext status-query reply (AA type 03; repeated three times):

```text
aa2fe600000000000003010114000100002924003c23290024501e280000002c2e0000006409007ffafa300000fafee0
```

Exact plaintext status notification (AA type 04):

```text
aa2fe600000000000004010114000100002924003c23290024501e280000002c2e0000006409007ffafa300000fafedf
```

The status reply and notification share an identical body; their message-type
byte and checksum differ. Body offsets here start at AA packet byte 10 and
exclude the trailing checksum. Selected library mappings:

| Body offset | Mapping | Captured value |
| --- | --- | --- |
| 2 | bit 2 main power; bit 4 heating working; bit 5 hot water working | 0x14 |
| 4 | bit 0 heating enabled; mode bits 2/3/4/5 | 0x01 |
| 8 | hot-water outlet temperature | 36 |
| 10 / 11 | hot-water maximum / minimum | 60 / 35 |
| 12 | hot-water target | 41 |
| 14 | heating outlet temperature | 36 |
| 15 / 16 | heating maximum / minimum | 80 / 30 |
| 17 | heating target | 40 |
| 25 | cold-water single/dot bits 0/1 | 0 |

### Cloud inspection

Reproducible offline command (uses the saved LAN session key locally and does not
print it):

```bash
.lan-venv/bin/python inspect_cloud_capture.py lan-captures/20261011T111010805399Z
```

`inspect_cloud_capture.py` stores the event snapshot as
`proxy-logs/inspection-events-snapshot.json` and analysis as
`proxy-logs/cloud-inspection.json`, both private. The snapshot ends at
2026-10-11T11:11:38.723245+00:00 and contains 544 cloud frames.
The proxy remains live, so later runs will include additional data.

| Cloud session | Frames | Captured stream bytes |
| --- | --- | --- |
| 20261011T104256577719Z-1 | 39 | 5694 |
| 20261011T104507129696Z-1 | 30 | 4280 |
| 20261011T104526796986Z-2 | 59 | 8790 |
| 20261011T105618001082Z-1 | 224 | 34196 |
| 20261011T110507785905Z-2 | 192 | 29172 |

For all ten direction streams, binary bytes matched concatenated logged frames
exactly at this snapshot; there were no incomplete or unlogged bytes. Five
complete cloud handshakes retain the earlier structure: device type 8 is 424
bytes, server type 1 is 168 bytes, device type 2 is 54 bytes. The SHA-256 trailer
matches wire bytes for types 8 and 1; type 2 does not use that wire-byte digest
formula. The same 128-byte type-8 field is stable across all five handshakes,
with SHA-256
`81a0771cc761233635d331ff781602b4401a831e6de9e2577c3f6e8ad993f0da`.
Its semantic role remains unknown.

During the seven-second LAN capture the cloud recorded:

| UTC time | Direction | Cloud outer type | Bytes |
| --- | --- | --- | --- |
| 11:10:11.164892 | device to cloud | 3 | 118 |
| 11:10:11.379770 | cloud to device | 3 | 134 |
| 11:10:11.398831 | device to cloud | 3 | 166 |

Cloud device-to-server 166-byte frames are common (latest session median interval
about 1.047 seconds). Decrypted LAN status messages also use 166-byte V3 frames.
This is consistent with similarly sized status envelopes, but does **not** prove
that cloud frames contain the same status payload. The fresh LAN session key was
tried with the LAN-style V3 decoder against all 529 cloud
type-3 frames: **zero passed SHA-256 verification**. This establishes that this
specific LAN session key does not decrypt these cloud frames under that decoder;
it does not establish the cloud key derivation, prove a different cipher, or
rule out some role for the persistent LAN device key. No cloud plaintext or
cloud session key has been recovered.

## 20. Raw LAN status packet structure

The captured status-query reply is a 48-byte AA appliance message:

```text
Header:   aa 2f e6 00 00 00 00 00 00 03
Body:     01 01 14 00 01 00 00 29 24 00 3c 23 29 00 24 50
          1e 28 00 00 00 2c 2e 00 00 00 64 09 00 7f fa fa
          30 00 00 fa fe
Checksum: e0
```

There are 37 body bytes. AA header offsets: 0 sync AA; 1 length 0x2f=47
(the serialized header plus body, before appending the checksum); 2 category
E6; 3–7 zero frame fields in this sample; 8 message protocol version 0;
9 message type 03 (query reply; notification uses 04). Checksum is the
8-bit two's complement of the sum of bytes from offset 1 through the end of
body, so summing all bytes after AA including the checksum gives zero modulo
256. Zero frame fields must not be assigned additional semantics from this
single sample.

The transport envelopes for this exact reply are:

| Layer | Structure | Size |
| --- | --- | --- |
| V3 TCP | 6-byte header + 128-byte ciphertext + 32-byte SHA-256 | 166 |
| V3 decrypted ciphertext | 2-byte sequence + 120-byte 5a5a packet + 6-byte padding | 128 |
| 5a5a packet | 40-byte header + 64-byte AES-ECB ciphertext + 16-byte MD5 | 120 |
| Appliance plaintext | 10-byte AA header + 37-byte body + 1-byte checksum | 48 |

V3 header is `8370009e2063`: length field 0x009e plus 8 gives total 166;
0x20 is the framing marker; 0x63 encodes six padding bytes and message type 3.
The V3 digest authenticates the six-byte header plus decrypted sequence/payload/
padding. Inner ciphertext decrypts to 48 appliance bytes plus a full 16-byte
PKCS#7 padding block. Its AES key is the library's fixed inner-packet key, while
the V3 layer uses the fresh session key. Neither key is reproduced here.

Body-field offsets and decoded values are in section 19. All other body offsets
are currently unassigned by the inspected E6 parser:
`0–1, 3, 5–7, 9, 13, 18–24, 26–36`. This includes byte 7=0x29 (41),
21=0x2c (44), 22=0x2e (46), 26=0x64 (100), and the trailing FA/FE values.
Their numeric resemblance to temperatures, percentages or sentinel values does
not identify their meaning. They require additional samples correlated with
known display/app values or a model-specific protocol definition. Mode and
power byte mappings remain library interpretations until independently checked.
This detailed raw structure is established for the decrypted LAN reply; the
cloud plaintext remains unavailable.

## 21. Temperature-change experiment and offline set decoding

The owner intends to change hot-water target to 45°C and heating target to 43°C.
`capture_lan_status.py` now supports longer read-only runs (`--samples` 1–300,
`--interval` 1–60 seconds), prints UTC timestamps and target transitions, and
stores transitions with exact AA response hex in `capture.json`. Ctrl-C saves
collected responses. Parser bookkeeping is omitted from status output.
Outbound commands remain restricted to protocol/status queries: this change
does not send either temperature setting.

Recommended experiment in the external terminal:

```bash
cd /Users/user/Projects/Midea
sudo .lan-venv/bin/python capture_lan_status.py --samples 60 --interval 2
sudo chown -R "$(id -u):$(id -g)" lan-captures
```

After about 20 seconds of baseline, change only hot-water target to 45°C through
the owner's controls. Wait about 20 seconds, then change only heating target to
43°C. Keep both values for the remainder of capture. Record which controls were
used (SmartHome app or boiler panel) and approximate change times. Keep the
cloud proxy running for timestamp correlation. Actual run duration exceeds two
minutes slightly due to query response times and protocol discovery; it is not
a fixed-duration recording.

Expected response-body changes based on the E6 mapping: offset 12 from 0x29
(41°C) to 0x2d (45°C), then offset 17 from 0x28 (40°C) to 0x2b (43°C).
Other bytes may also change; they must be compared rather than assumed stable.

The decoder recognizes AA type 02 temperature-set bodies with library selectors
`04 12 <temperature>` for hot water and `04 13 <temperature>` for heating,
followed by zero padding to a 30-byte body. Unknown selectors or body lengths
are preserved as raw hex rather than guessed. Nonzero trailing bytes are
reported. An inbound type-02 frame is labeled as a set message, since direction
and context are needed to distinguish a command from its response.

Library-generated, synthetic set packets for the requested temperatures:

```text
Hot water 45°C:
aa28e60000000000000204122d000000000000000000000000000000000000000000000000000000ad
Heating 43°C:
aa28e60000000000000204132b000000000000000000000000000000000000000000000000000000ae
```

These were generated offline for decoder verification and were **not sent**.
Round-trip inner encryption/decryption, checksum verification, recognized
selectors/temperatures, unknown/short body handling and decoding existing
captured status responses passed.

Offline decoding of a saved decrypted V3 payload (a complete 5a5a packet):

```bash
.lan-venv/bin/python capture_lan_status.py --decode-inner-file /path/to/inner-packet.bin
```

Important observation limit: the polling script sees only its own authenticated
LAN connection and any notifications sent on that connection. SmartHome cloud
commands traverse another encrypted session and are not made visible by this
script. This experiment can validate target fields and correlate cloud frames
with changes; it cannot establish the actual cloud set-command plaintext. To
capture an actual LAN set command, obtain a sender-side packet log or a complete
bidirectional capture of the LAN client's connection, including its fresh
handshake and the appropriate token/key for offline decryption. Boiler-panel
changes need not emit any LAN set command at all.


## 22. SmartHome temperature-change experiment results

The owner used SmartHome on a phone connected to the same LAN as the boiler.
Capture `20261011T114445270031Z` spans 11:44:45.270280–11:45:28.907776 UTC
on 2026-10-11. It was interrupted cleanly, with 19 status queries and one protocol
query completed: 19 status replies plus 16 notifications. All 36 encrypted
protocol/status replies were independently decrypted and verified by
`inspect_cloud_capture.py`; there was no capture error.

```bash
.lan-venv/bin/python inspect_cloud_capture.py lan-captures/20261011T114445270031Z
```

Exact before/after evidence is also saved in private
`lan-captures/20261011T114445270031Z/temperature-change-analysis.json`.

First observed UTC: 2026-10-11T11:45:02.805382+00:00. Targets changed from
`{'bathing_temperature': 41.0, 'heating_temperature': 40.0}` to `{'bathing_temperature': 45.0, 'heating_temperature': 40.0}`.
Only these body bytes changed between the immediate status samples:
`[{'offset': 12, 'before_hex': '29', 'after_hex': '2d'}]`.

Before:

```text
aa2fe60000000000000301011c000100002923013c2329002a501e280000002c2e0000006409007ffafa1a0011fafed7
```

After:

```text
aa2fe60000000000000401011c000100002923013c232d002a501e280000002c2e0000006409007ffafa1a0011fafed2
```

First observed UTC: 2026-10-11T11:45:16.077175+00:00. Targets changed from
`{'bathing_temperature': 45.0, 'heating_temperature': 40.0}` to `{'bathing_temperature': 45.0, 'heating_temperature': 43.0}`.
Only these body bytes changed between the immediate status samples:
`[{'offset': 17, 'before_hex': '28', 'after_hex': '2b'}]`.

Before:

```text
aa2fe60000000000000301011c000100002923013c232d0029501e280000002c2e0000006409007ffafa1a000efafed7
```

After:

```text
aa2fe60000000000000301011c000100002923013c232d0029501e2b0000002c2e0000006409007ffafa1a000efafed4
```

Thus hot-water target is empirically confirmed at zero-based body offset 12
(AA packet offset 22), with integer Celsius 41→45 (`29→2d`). Heating target
is confirmed at body offset 17 (AA offset 27), with 40→43 (`28→2b`).
Timestamps mark first observation, not necessarily the exact command time.
Other body bytes varied over the whole run as the boiler operated.

No AA type-02 messages were captured on the polling connection. The cloud
proxy recorded no cloud-to-device frames within two seconds of either first
observed transition. Around the full run its incoming frames occurred at
11:44:45.695916 (134 bytes) and 11:45:26.036996 (102 bytes). The phone sharing
the LAN makes a separate local control connection a plausible explanation,
but this remains a hypothesis until the phone-to-boiler connection is captured.
The current experiment validates status target offsets, not the synthetic
set-command layout or cloud command plaintext. A passive capture of all boiler
TCP port-6444 traffic, starting before SmartHome reconnects, is needed to
observe its separate LAN handshake and potential set commands.

## 23. Passive SmartHome experiment capture: cloud flow only

The owner completed `midea-app-lan.pcap` with the section-22 TZSP receiver.
The file contains 52 packets spanning 2026-10-11 11:49:56.991528 to
11:51:55.199039 UTC (~118.208 seconds): 50 TCP packets and two DHCP packets.
Only one TCP conversation is observed:
`192.168.200.133:58203 ↔ 35.71.136.152:28443`. No TCP port-6444 traffic,
new TCP handshake, or new Midea authentication handshake is present. It starts
midway through the already-established cloud connection. It therefore cannot
supply a SmartHome LAN handshake/session key for set-command decryption.
Absence from this capture does not exclude local traffic missed by the capture
point; the previous same-LAN control hypothesis remains unproven.

Inspection commands:

```bash
tshark -n -r midea-app-lan.pcap -q -z conv,tcp
tshark -n -r midea-app-lan.pcap -Y 'tcp.port == 6444'
tshark -n -r midea-app-lan.pcap -Y 'tcp.len > 0' -T fields \
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport -e tcp.payload > midea-app-lan-payloads.tsv
```

Exact application payloads and proxy matches are saved in
`midea-app-lan-analysis.json`; the TSV preserves the packet-level payloads.
All 27 application frames match byte-for-byte with frames in proxy session
`20261011T110507785905Z-2`. Frame counts:

| Direction | Cloud outer type | Length | Count |
| --- | --- | --- | --- |
| Device to cloud | 3 | 166 | 17 |
| Device to cloud | 3 | 118 | 1 |
| Device to cloud | 3 | 102 | 2 |
| Cloud to device | 3 | 134 | 5 |
| Cloud to device | 3 | 102 | 2 |

The five 134-byte incoming packets are frames 11, 16, 26, 32, 34 at UTC times
11:50:07.343809, 11:50:08.315999, 11:50:14.961125, 11:50:15.852021,
11:50:16.109398 (TZSP receiver timestamps). Their header is
`8370007e2063`: 134-byte frame, six padding bytes, outer type 3. They are
followed by 166-byte outgoing frames consistent in size with status traffic.
This burst could include SmartHome queries or settings but **cannot be labeled
as set commands without decryption or stronger sender-side evidence**.
The 102-byte incoming packets at 11:50:56.362972 and 11:51:36.602642 have
header `8370005e2063` and are 40.240 seconds apart; their semantic role is
also unverified.

The packet capture corroborates the proxy recording rather than providing new
plaintext. Existing status target offsets remain verified; actual SmartHome
set-command bytes remain unknown. Merely repeating the same capture procedure
cannot decrypt this cloud session. Further progress requires recovering its
cloud session key, obtaining a plaintext command log from the sender, or
capturing a client that actually sends authenticated LAN commands. The library's
synthetic temperature-set layouts remain hypotheses for SmartHome cloud traffic.

## 24. Project files

The table lists project files and groups generated artifacts by directory.
“Ignored” means excluded by `.gitignore`; it does not imply deletion.

| File or directory | Description | Git policy |
| --- | --- | --- |
| `README.md` | Main research record: setup, commands, exact payloads, protocol findings, and experiment results. | Included |
| `README_RAW.md` | Original README preserved before username sanitization. | Ignored |
| `.gitignore` | Excludes private notes, certificates, credentials, secret artifacts, captures containing LAN tokens, and Python environments. | Included |
| `capture_tzsp.py` | Receives MikroTik TZSP UDP streams and writes decapsulated Ethernet packets to PCAP. | Included |
| `local_server.py` | Records and relays appliance/cloud traffic unchanged; also provides HTTP/HTTPS status endpoints. | Included |
| `verify_local_server.py` | Offline tests for bidirectional proxy forwarding, frame logging, and connection cleanup. | Included |
| `obtain_lan_key.py` | Retrieves candidate LAN credentials from the selected Midea account backend and verifies them against the boiler's V3 handshake. | Included |
| `run_lan_key.sh` | Creates the isolated Python environment, installs dependencies, and launches LAN credential retrieval. | Included |
| `capture_lan_status.py` | Opens an authenticated LAN session, captures read-only protocol/status replies, decrypts payloads, records target changes, and supports offline temperature-set message decoding. | Included |
| `inspect_cloud_capture.py` | Compares proxy logs with a LAN capture, revalidates decrypted replies, checks stream consistency, and tests the LAN session key against cloud frames. | Included |
| `router-redirect.rsc` | MikroTik NAT rules forwarding the boiler's cloud connection through the recording proxy, with inspection instructions. | Included |
| `cloud-auth-findings.md` | Earlier notes on the cloud type-8/1/2 handshake and unresolved authentication/key derivation. | Included |
| `midea-inner.pcap` | Initial decapsulated packet capture of established appliance/cloud traffic. | Included |
| `midea-payloads.tsv` | TCP application payload export from the initial capture. | Included |
| `midea-ack-times.txt` | ACK timing data from the initial capture. | Included |
| `midea-reboot.pcap` | Reboot capture containing discovery broadcasts, DNS/DHCP, and a new cloud handshake. | Included |
| `midea-reboot-payloads.tsv` | TCP payload export from the reboot capture. | Included |
| `midea-reboot-broadcasts.tsv` | UDP discovery broadcast export from the reboot capture. | Included |
| `midea-reboot-handshake.json` | Exact captured cloud authentication request, response, and confirmation frames. | Included |
| `midea-reboot-selected-udp.json` | Selected DNS and appliance discovery UDP payloads. | Included |
| `midea-discovery-plaintext.bin` | Decrypted discovery data used to identify the boiler and its advertised LAN port. | Included |
| `midea-app-lan.pcap` | Passive SmartHome experiment capture; despite its name, only cloud TCP and DHCP traffic were observed. | Included |
| `midea-app-lan-payloads.tsv` | TCP payload export from the passive SmartHome experiment. | Included |
| `midea-app-lan-analysis.json` | Frame sizes, directions, exact encrypted payloads, and matching proxy records for that experiment. | Included |
| `proxy-analysis-snapshot.json` | Earlier snapshot of proxy events used for cloud handshake analysis. | Included |
| `proxy-handshakes.json` | Extracted type-8/1/2 frames from the first three recorded proxy sessions. | Included |
| `certs/openssl.cnf` | Configuration used to generate the local server's self-signed certificate. | Ignored |
| `certs/server.crt` | Self-signed local HTTPS server certificate. | Ignored |
| `certs/server.key` | Private key corresponding to the local HTTPS certificate. | Ignored |
| `lan-secrets/credentials.json` | Verified persistent boiler LAN token/key and device identity. | Ignored |
| `lan-secrets/handshake.json` | Credential-verification handshake, decrypted challenge, and connection-specific session key. | Ignored |
| `lan-captures/<timestamp>/capture.json` | LAN capture metadata, wire/inner/appliance payloads, integrity checks, statuses, and target transitions. | Ignored |
| `lan-captures/<timestamp>/*-tx.bin`, `*-rx.bin` | Individual transmitted and received LAN frames, including authentication traffic. | Ignored |
| `lan-captures/<timestamp>/session-secret.json` | Session key for decrypting that captured LAN connection. | Ignored |
| `lan-captures/<timestamp>/temperature-change-analysis.json` | Before/after status payloads and byte differences for the SmartHome temperature experiment. | Ignored |
| `proxy-logs/events.jsonl` | Append-only recording proxy events, timestamps, and cloud frame hex. | Ignored |
| `proxy-logs/*-device-to-cloud.bin`, `*-cloud-to-device.bin` | Raw byte streams for each proxied cloud connection and direction. | Ignored |
| `proxy-logs/inspection-events-snapshot.json` | Snapshot of proxy events taken by the offline inspection script. | Ignored |
| `proxy-logs/cloud-inspection.json` | Latest offline cloud/LAN comparison and verification results. | Ignored |
| `.lan-venv/` | Python environment containing the installed `midea-local` library and dependencies. | Ignored |
| `.venv/` | Earlier Python environment created during setup. | Ignored |
| `.uv-cache/` | Local uv package-manager cache. | Ignored |
| `__pycache__/` | Generated Python bytecode. | Ignored |
