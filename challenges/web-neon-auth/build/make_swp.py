#!/usr/bin/env python3
"""
Vim swap file generator for the CTF challenge (build-time only).
Creates /var/www/html/.index.php.swp that recovers via: vim -r .index.php.swp
This is the intended source-disclosure artifact.
"""
import struct, os, time, socket

PAGE = 4096

def pad(data, size):
    return data[:size].ljust(size, b'\x00')

src = open('/var/www/html/index.php', 'rb').read()

# --- Block 0: header ---
b0  = b'b0VIM 8.2\n'           # id (10 bytes)
b0 += struct.pack('<I', PAGE)   # page size
b0 += struct.pack('<I', 2)      # nr of used blocks
b0 += struct.pack('<I', 0)      # inode (dummy)
b0 += struct.pack('<I', 0)      # device (dummy)
b0 += struct.pack('<I', 0)      # timestamp
b0 += pad(b'root',    40)       # last user
b0 += pad(socket.gethostname().encode(), 40)  # hostname
b0 += pad(b'/var/www/html/index.php', 900)    # file name
b0 += pad(b'utf-8',   80)       # encoding
b0 = pad(b0, PAGE)

# --- Block 1: content (raw text, NUL-line-separated like vim does) ---
# Vim stores lines separated by NUL bytes in the swap file blocks
content = src.replace(b'\n', b'\x00')
b1 = pad(content, PAGE * ((len(content) // PAGE) + 1))

with open('/var/www/html/.index.php.swp', 'wb') as f:
    f.write(b0)
    f.write(b1)

print("Created .index.php.swp ({} bytes)".format(os.path.getsize('/var/www/html/.index.php.swp')))
