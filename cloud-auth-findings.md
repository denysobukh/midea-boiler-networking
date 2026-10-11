# Midea cloud authentication investigation

Capture: `midea-reboot.pcap`, device `192.168.200.133`, cloud
`module-us.msmartlife.net` / `35.71.136.152:28443`.

Appliance model supplied by owner: `L1PB20-C28WM(WIFI)`. Midea's official
product page identifies this as a Wi-Fi gas central-heating boiler. The
captured device type/name `E6` agrees with the gas-boiler category supported
by midea-local. The exact Wi-Fi module hardware and firmware remain unknown;
the boiler model does not establish its chipset or cloud root credential.

Model references:

- https://www.midea.com/ge-en/water-heaters/gas-boiler/gas-boiler-l1pb18-c28wm.l1pb20-c28wm
- https://github.com/midea-lan/midea-local/blob/main/midealocal/devices/e6/__init__.py

The outer framing and two handshake checksums are identified. The cloud
credential format and session-key derivation remain unidentified. No cloud
payload has been successfully decrypted.

## Verified packet structure

Offsets are zero-based from the start of the TCP payload.

| Packet | Frame | Header | Total bytes | Observed structure |
| --- | --- | --- | --- | --- |
| Device initial message | 26 | `837001a02008` | 424 | 6-byte header, `0000`, 384 opaque bytes, 32-byte SHA-256 |
| Server response | 28 | `837000a02001` | 168 | 6-byte header, `0000`, 128 opaque bytes, 32-byte SHA-256 |
| Device next message | 30 | `8370002e20b2` | 54 | 6-byte header, 16 opaque bytes, 32-byte tail |

For frames 26 and 28, the last 32 bytes equal
`SHA256(packet[:-32])` exactly. This is an unkeyed checksum of the bytes on
the wire. It does not authenticate the peer by itself, and does not establish
whether the opaque fields contain ciphertext, tokens, or other credentials.

Both initial `0000` values are consistent with a clear two-byte packet counter.
Their interpretation as counters is inferred from the LAN framing, rather than
proven by this single cloud handshake.

Frame 30 does not have a SHA-256 checksum of its preceding wire bytes. Its
six-byte header is followed by exactly one 16-byte block and a 32-byte tail.
If cloud type 2 follows the LAN encrypted-packet convention, `b2` means 11
padding bytes and message type 2. The decrypted block would then have two
counter bytes, three application bytes, and 11 padding bytes. This is a
testable hypothesis, not a recovered plaintext or confirmed cloud specification.

## Key checks

Under the known LAN AES-CBC convention (zero IV, trailing SHA-256 of header
plus decrypted padded body), 64 candidate keys were checked against both frame
30 and the first type 3 packet, frame 31. These were the aligned 16- and
32-byte slices of the opaque initial-message and response fields, plus the
published discovery AES key and app-internal key from midea-beautiful-air.
No candidate produced a valid digest. This rules out those specific direct-key
interpretations under that convention; it does not establish the actual cloud
cipher, IV, root key, or derivation.

## Discovery metadata recovered

The first UDP broadcast contains an outer transparent type `0xF` frame and
an inner `5a5a` frame. The inner declared length is 184 bytes; use that length
before locating its 16-byte MD5 trailer. Its MD5 checksum validates with the
published discovery signing constant. Its body decrypts successfully using
AES-128-ECB with `MD5(signing_constant)` and PKCS#7 unpadding.

Recovered values:

- Device ID: `151732607790550`.
- Serial: `0000E65412760002446141A00394N925`.
- Name: `midea_e6_0394`.
- Advertised IP: `192.168.200.133`.
- Advertised TCP port: `6444`.
- MAC also appears in decrypted discovery data: `b8:0b:da:ce:a2:30`.

The successful discovery decryption does not decrypt the cloud session.
The plaintext is saved separately in `midea-discovery-plaintext.bin`.

## What is known about LAN key derivation

The reference LAN implementation sends a type 0 request with a token, then
expects a type 1 response containing 32 encrypted bytes and a 32-byte digest:

```
R = AES-CBC-decrypt(device_key, IV=0, response_ciphertext_32)
require SHA256(R) == response_digest_32
LAN_session_key = R XOR device_key
```

The cloud's 128 opaque response bytes and 384 opaque request bytes differ
from this format. Applying the LAN derivation without identifying the cloud
fields and root credential is unsupported.

## Remaining evidence needed

A firmware image or dump from this device's Wi-Fi module is the most direct
way to determine the cloud credential parser, cryptographic calls, and exact
session-key derivation. Another complete reboot capture could establish which
initial fields are stable versus per-session, but cannot by itself guarantee
recovery of a secret key.

No active probes or modifications to the appliance or router were performed.

Sources inspected:

- https://github.com/mill1000/midea-msmart/blob/master/msmart/lan.py
- https://github.com/nbogojevic/midea-beautiful-air/blob/main/midea_beautiful/crypto.py
- https://github.com/nbogojevic/midea-beautiful-air/blob/main/midea_beautiful/midea.py
- https://maxammann.org/posts/2026/05/notes-midea-portasplit/

The inspected implementations document LAN authentication; the inspected
firmware research reports the same cloud framing but no cloud key derivation.
