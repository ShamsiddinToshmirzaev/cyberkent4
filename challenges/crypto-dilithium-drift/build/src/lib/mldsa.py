"""Textbook ML-DSA (Dilithium) for C12 "Dilithium Drift".

Fiat-Shamir with aborts over Module-LWE, ML-DSA-44-style parameters. This is the
*uncompressed* textbook variant: the public key carries the full t (no t0/hint
compression), so verify recomputes HighBits(A z - c t) directly. That keeps the code
self-contained and auditable; the challenge's flaw is a nonce-telemetry contract bug,
not the primitive.

sign(pk, mu, leak_fn=...) calls leak_fn(y) with the accepted masking vector y so the
QA-telemetry layer can report its "monitored lane levels".
"""
import hashlib

N=256; Q=8380417
PSI=1753; W=pow(PSI,2,Q)
ETA=2; TAU=39; GAMMA1=1<<17; GAMMA2=(Q-1)//88; BETA=TAU*ETA
K=4; L=4

def _brev(x,bits):
    r=0
    for _ in range(bits): r=(r<<1)|(x&1); x>>=1
    return r
_BR=[_brev(i,8) for i in range(N)]
_WPOW=[pow(W,i,Q) for i in range(N)]
_WINV=[pow(W,(-i)%(Q-1),Q) for i in range(N)]
_PSIPOW=[pow(PSI,i,Q) for i in range(N)]
_PSIINV=[pow(PSI,(-i)%(Q-1),Q) for i in range(N)]
_NINV=pow(N,Q-2,Q)

def _ntt(a):
    a=[a[_BR[i]] for i in range(N)]
    length=1
    while length<N:
        step=N//(2*length)
        for start in range(0,N,2*length):
            for j in range(length):
                w=_WPOW[step*j]
                u=a[start+j]; v=a[start+j+length]*w%Q
                a[start+j]=(u+v)%Q; a[start+j+length]=(u-v)%Q
        length*=2
    return a

def _intt(a):
    a=list(a)
    length=N//2
    while length>=1:
        step=N//(2*length)
        for start in range(0,N,2*length):
            for j in range(length):
                w=_WINV[step*j]
                u=a[start+j]; v=a[start+j+length]
                a[start+j]=(u+v)%Q; a[start+j+length]=(u-v)*w%Q
        length//=2
    out=[0]*N
    for i in range(N): out[_BR[i]]=a[i]*_NINV%Q
    return out

def polymul(a,b):
    # negacyclic mult in Z_q[X]/(X^256+1)
    fa=_ntt([a[i]*_PSIPOW[i]%Q for i in range(N)])
    fb=_ntt([b[i]*_PSIPOW[i]%Q for i in range(N)])
    fc=[fa[i]*fb[i]%Q for i in range(N)]
    c=_intt(fc)
    return [c[i]*_PSIINV[i]%Q for i in range(N)]

def polymul_school(a,b):
    r=[0]*N
    for i in range(N):
        if a[i]==0: continue
        ai=a[i]
        for j in range(N):
            k=i+j
            if k<N: r[k]=(r[k]+ai*b[j])%Q
            else:   r[k-N]=(r[k-N]-ai*b[j])%Q
    return [x%Q for x in r]

def vadd(x,y): return [(a+b)%Q for a,b in zip(x,y)]
def vsub(x,y): return [(a-b)%Q for a,b in zip(x,y)]

# ---------------- scheme ----------------
def _shake(data,n):
    return hashlib.shake_256(data).digest(n)

def _cbd_eta(seed, nonce, count):
    # produce `count` polynomials with coeffs in [-ETA,ETA] from seed
    out=[]
    for p in range(count):
        buf=_shake(seed+bytes([nonce,p]), N*2)
        poly=[]
        for i in range(N):
            v=(buf[2*i] ^ (buf[2*i+1]<<8)) % (2*ETA+1)
            poly.append((v-ETA)%Q)
        out.append(poly)
    return out

def expand_A(rho):
    A=[[None]*L for _ in range(K)]
    for i in range(K):
        for j in range(L):
            buf=_shake(rho+bytes([j,i]), N*3)
            poly=[]
            idx=0
            while len(poly)<N:
                b0,b1,b2=buf[idx],buf[idx+1],buf[idx+2]; idx+=3
                val=(b0 | (b1<<8) | ((b2&0x7f)<<16))
                if val<Q: poly.append(val)
                if idx+3>len(buf): buf+=_shake(rho+bytes([j,i,len(buf)&0xff]),N*3)
            A[i][j]=poly
    return A

def sample_in_ball(seed):
    buf=_shake(seed, 8+ (TAU+7)//8*0 + 256)
    c=[0]*N
    signs=int.from_bytes(buf[:8],"little")
    pos=8
    for i in range(N-TAU, N):
        j=buf[pos]; pos+=1
        while j>i:
            j=buf[pos]; pos+=1
        c[i]=c[j]
        c[j]=1 if (signs&1)==0 else Q-1
        signs>>=1
    return c

def _mv(A,v):  # matrix (K x L) times vec length L -> length K, poly entries
    out=[]
    for i in range(K):
        acc=[0]*N
        for j in range(L):
            acc=vadd(acc, polymul(A[i][j], v[j]))
        out.append(acc)
    return out

def _center(x):  # to (-Q/2, Q/2]
    x%=Q
    return x-Q if x>Q//2 else x

def decompose(r):
    a=2*GAMMA2
    r=r%Q
    r0=r%a
    if r0>a//2: r0-=a
    if r-r0==Q-1: return 0,r0-1
    return (r-r0)//a, r0

def highbits(poly): return [decompose(x)[0] for x in poly]
def lowbits(poly):  return [decompose(x)[1] for x in poly]
def infnorm(poly):  return max(abs(_center(x)) for x in poly)

def _encode_w1(w1vec):
    out=bytearray()
    for w1 in w1vec:
        for x in w1:
            out.append(x&0xff); out.append((x>>8)&0xff)
    return bytes(out)

def keygen(seed):
    xof=_shake(seed,128)
    rho=xof[:32]; rhoprime=xof[32:96]; key=xof[96:128]
    A=expand_A(rho)
    s1=_cbd_eta(rhoprime,0,L)
    s2=_cbd_eta(rhoprime,1,K)
    t=[vadd(_mv(A,s1)[i], s2[i]) for i in range(K)]
    return dict(A=A,rho=rho,key=key,t=t,s1=s1,s2=s2)

def _expand_mask(seed, kappa):
    # y in (-GAMMA1, GAMMA1], L polys; deterministic from seed||kappa
    ys=[]
    for j in range(L):
        buf=_shake(seed+bytes([kappa&0xff,(kappa>>8)&0xff, j]), N*4)
        poly=[]
        for i in range(N):
            v=int.from_bytes(buf[4*i:4*i+4],"little") % (2*GAMMA1)
            poly.append((GAMMA1-1-v)%Q)
        ys.append(poly)
    return ys

def sign(pk, mu, kappa0=0, leak_fn=None):
    A=pk["A"]; s1=pk["s1"]; s2=pk["s2"]; key=pk["key"]
    rhoprime=_shake(key+mu,64)
    kappa=kappa0
    while True:
        y=_expand_mask(rhoprime,kappa); kappa+=1
        w=_mv(A,y)
        w1=[highbits(w[i]) for i in range(K)]
        cseed=_shake(mu+_encode_w1(w1),32)
        c=sample_in_ball(cseed)
        z=[vadd(y[j], polymul(c,s1[j])) for j in range(L)]
        if max(infnorm(z[j]) for j in range(L))>=GAMMA1-BETA: continue
        r0=[lowbits(vsub(w[i], polymul(c,s2[i]))) for i in range(K)]
        if max(max(abs(_center(x)) for x in r0[i]) for i in range(K))>=GAMMA2-BETA: continue
        if leak_fn is not None: leak_fn(y)
        return dict(c=c, z=z, cseed=cseed)

def verify(pk, mu, sig):
    """Verify sig = {"cseed": <32-byte hex/bytes>, "z": [L polys]}.
    The challenge polynomial is DERIVED from cseed here (never taken from the caller),
    so a forged c cannot be injected."""
    A=pk["A"]; t=pk["t"]
    cseed=sig["cseed"]
    if isinstance(cseed,str): cseed=bytes.fromhex(cseed)
    z=sig["z"]
    if len(z)!=L or any(len(zj)!=N for zj in z): return False
    if max(infnorm(z[j]) for j in range(L))>=GAMMA1-BETA: return False
    c=sample_in_ball(cseed)
    Az=_mv(A,z)
    ct=[polymul(c,t[i]) for i in range(K)]
    w1p=[highbits(vsub(Az[i],ct[i])) for i in range(K)]
    return _shake(mu+_encode_w1(w1p),32)==cseed
