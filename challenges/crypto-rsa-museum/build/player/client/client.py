#!/usr/bin/env python3
"""Minimal client for C18 "RSA Museum".

  python3 client.py info
  python3 client.py sign <artifact> [glitch]
  python3 client.py issue <artifact> <signature-hex>
"""
import json, os, sys, urllib.request
HERE=os.path.dirname(os.path.abspath(__file__)); SAMPLES=os.path.join(os.path.dirname(HERE),"samples")
def base():
    pub=json.load(open(os.path.join(SAMPLES,"instance_public.json")))
    return f"http://{pub['gateway_host']}:{pub['gateway_port']}"
def _get(p):
    with urllib.request.urlopen(base()+p,timeout=30) as r: return json.load(r)
def _post(p,o):
    req=urllib.request.Request(base()+p,data=json.dumps(o).encode(),headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=60) as r: return json.load(r)
def main(a):
    if not a: print(__doc__); return 2
    if a[0]=="info": print(json.dumps(_get("/info"),indent=2))
    elif a[0]=="sign": print(json.dumps(_post("/sign",{"artifact":a[1],"glitch":int(a[2]) if len(a)>2 else 0}),indent=2))
    elif a[0]=="issue": print(json.dumps(_post("/issue",{"artifact":a[1],"signature":a[2]}),indent=2))
    else: print(__doc__); return 2
    return 0
if __name__=="__main__": sys.exit(main(sys.argv[1:]))
