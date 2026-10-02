"""RSA-2048 with CRT signing + EMSA-PSS (RFC 8017), pure Python, for C18 "RSA Museum".

NOTE (the contract bug): the PSS salt is derived deterministically from the message
(`det_salt`) instead of being random, so a message re-signs to the SAME encoded EM. That is
what makes a CRT single-branch fault exploitable via gcd(s_correct - s_faulty, N).

sign(key, msg, faulty=True, rng=...) corrupts exactly one CRT branch (Bellcore fault).
"""
import hashlib, os, random, math

def _is_probable_prime(n, rng, k=20):
    if n < 2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0: return n == p
    d=n-1; r=0
    while d%2==0: d//=2; r+=1
    for _ in range(k):
        a=rng.randrange(2,n-1)
        x=pow(a,d,n)
        if x==1 or x==n-1: continue
        for _ in range(r-1):
            x=x*x%n
            if x==n-1: break
        else: return False
    return True

def _gen_prime(bits, rng):
    while True:
        c=rng.getrandbits(bits) | (3<<(bits-2)) | 1
        if _is_probable_prime(c, rng): return c

def keygen(bits, rng, e=65537):
    while True:
        p=_gen_prime(bits//2, rng); q=_gen_prime(bits//2, rng)
        if p==q: continue
        n=p*q; phi=(p-1)*(q-1)
        if math.gcd(e,phi)!=1: continue
        d=pow(e,-1,phi)
        return dict(n=n,e=e,d=d,p=p,q=q,dp=d%(p-1),dq=d%(q-1),qinv=pow(q,-1,p),
                    bits=bits,embits=n.bit_length()-1)

# ---- EMSA-PSS ----
H=hashlib.sha256; HLEN=32; SLEN=32
def _mgf1(seed, length):
    out=b""; i=0
    while len(out)<length:
        out+=H(seed+i.to_bytes(4,"big")).digest(); i+=1
    return out[:length]

def det_salt(msg):  # THE BUG: PSS salt derived from the message (must be random)
    return H(b"museum-salt|"+msg).digest()[:SLEN]

def pss_encode(msg, embits, salt=None):
    emlen=(embits+7)//8
    mhash=H(msg).digest()
    if salt is None: salt=det_salt(msg)
    mp=b"\x00"*8+mhash+salt
    h=H(mp).digest()
    ps=b"\x00"*(emlen-SLEN-HLEN-2)
    db=ps+b"\x01"+salt
    dbmask=_mgf1(h, emlen-HLEN-1)
    maskeddb=bytes(a^b for a,b in zip(db,dbmask))
    # clear leftmost bits
    bits_to_clear=8*emlen-embits
    maskeddb=bytes([maskeddb[0]&(0xFF>>bits_to_clear)])+maskeddb[1:]
    return maskeddb+h+b"\xbc"

def pss_verify(msg, em, embits):
    emlen=(embits+7)//8
    if len(em)!=emlen or em[-1]!=0xbc: return False
    maskeddb=em[:emlen-HLEN-1]; h=em[emlen-HLEN-1:-1]
    bits_to_clear=8*emlen-embits
    if maskeddb[0]>>(8-bits_to_clear) != 0 and bits_to_clear>0: return False
    dbmask=_mgf1(h, emlen-HLEN-1)
    db=bytes(a^b for a,b in zip(maskeddb,dbmask))
    db=bytes([db[0]&(0xFF>>bits_to_clear)])+db[1:]
    if any(db[i]!=0 for i in range(emlen-SLEN-HLEN-2)): return False
    if db[emlen-SLEN-HLEN-2]!=0x01: return False
    salt=db[-SLEN:]
    mhash=H(msg).digest()
    mp=b"\x00"*8+mhash+salt
    return H(mp).digest()==h

def sign(key, msg, faulty=False, rng=None):
    embits=key["embits"]
    em=pss_encode(msg, embits)
    m=int.from_bytes(em,"big")
    p,q,dp,dq,qinv=key["p"],key["q"],key["dp"],key["dq"],key["qinv"]
    sp=pow(m,dp,p); sq=pow(m,dq,q)
    if faulty:
        # corrupt exactly one CRT branch (Bellcore single-fault)
        if (rng or random).random()<0.5: sp=(sp+ (rng or random).randrange(1,p))%p
        else: sq=(sq+ (rng or random).randrange(1,q))%q
    s=(sq + q*((qinv*(sp-sq))%p))%key["n"]
    return s

def verify(key, msg, s):
    embits=key["embits"]
    m=pow(s,key["e"],key["n"])
    emlen=(embits+7)//8
    em=m.to_bytes(emlen,"big") if m.bit_length()<=8*emlen else None
    if em is None: return False
    return pss_verify(msg, em, embits)
