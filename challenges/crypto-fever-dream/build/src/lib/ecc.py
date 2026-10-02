"""Lightweight ECDSA over secp128r1 (a real standardized 128-bit curve) for C04.

Deterministic (RFC6979-style) nonces so a command re-signs identically, which lets the
player average repeated power measurements of the same command. Jacobian scalar mult.
"""
import hashlib, hmac

P  = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF
A  = 0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC
B  = 0xE87579C11079F43DD824993C2CEE5ED3
GX = 0x161FF7528B899B2D0C28607CA52C5B86
GY = 0xCF5AC8395BAFEB13C02DA292DDED7A83
N  = 0xFFFFFFFE0000000075A30D1B9038A115

def inv(a,m): return pow(a% m,-1,m)

def add(Pt,Qt):
    # affine add (used rarely, e.g. in verify)
    if Pt is None: return Qt
    if Qt is None: return Pt
    x1,y1=Pt; x2,y2=Qt
    if x1==x2 and (y1+y2)%P==0: return None
    if Pt==Qt:
        l=(3*x1*x1+A)*inv(2*y1,P)%P
    else:
        l=(y2-y1)*inv((x2-x1)%P,P)%P
    x3=(l*l-x1-x2)%P
    y3=(l*(x1-x3)-y1)%P
    return (x3,y3)

def _jdouble(X1,Y1,Z1):
    if Y1==0: return (0,0,0)
    S=(4*X1*Y1*Y1)%P
    M=(3*X1*X1 + A*pow(Z1,4,P))%P
    X3=(M*M-2*S)%P
    Y3=(M*(S-X3)-8*pow(Y1,4,P))%P
    Z3=(2*Y1*Z1)%P
    return (X3,Y3,Z3)

def _jadd(X1,Y1,Z1,X2,Y2,Z2):
    if Z1==0: return (X2,Y2,Z2)
    if Z2==0: return (X1,Y1,Z1)
    Z1Z1=Z1*Z1%P; Z2Z2=Z2*Z2%P
    U1=X1*Z2Z2%P; U2=X2*Z1Z1%P
    S1=Y1*Z2*Z2Z2%P; S2=Y2*Z1*Z1Z1%P
    if U1==U2:
        if S1!=S2: return (0,0,0)
        return _jdouble(X1,Y1,Z1)
    H=(U2-U1)%P; R=(S2-S1)%P
    HH=H*H%P; HHH=H*HH%P
    V=U1*HH%P
    X3=(R*R-HHH-2*V)%P
    Y3=(R*(V-X3)-S1*HHH)%P
    Z3=(Z1*Z2*H)%P
    return (X3,Y3,Z3)

def mul(k,Pt):
    if Pt is None: return None
    k%=N
    if k==0: return None
    X,Y,Z=Pt[0],Pt[1],1
    RX,RY,RZ=0,0,0  # infinity
    while k:
        if k&1: RX,RY,RZ=_jadd(RX,RY,RZ,X,Y,Z)
        X,Y,Z=_jdouble(X,Y,Z); k>>=1
    if RZ==0: return None
    Zi=inv(RZ,P); Zi2=Zi*Zi%P
    return (RX*Zi2%P, RY*Zi2*Zi%P)

G=(GX,GY)
def pubkey(d): return mul(d,G)

def _bits2int(b):
    x=int.from_bytes(b,"big")
    excess=len(b)*8 - N.bit_length()
    return x>>excess if excess>0 else x

def det_nonce(d,z):
    # RFC6979-style deterministic nonce (HMAC-SHA256), reduced mod N
    h1=z.to_bytes(16,"big")
    dk=d.to_bytes(16,"big")
    v=b"\x01"*32; k=b"\x00"*32
    k=hmac.new(k,v+b"\x00"+dk+h1,hashlib.sha256).digest(); v=hmac.new(k,v,hashlib.sha256).digest()
    k=hmac.new(k,v+b"\x01"+dk+h1,hashlib.sha256).digest(); v=hmac.new(k,v,hashlib.sha256).digest()
    while True:
        v=hmac.new(k,v,hashlib.sha256).digest()
        cand=_bits2int(v)%N
        if 1<=cand<N: return cand
        k=hmac.new(k,v+b"\x00",hashlib.sha256).digest(); v=hmac.new(k,v,hashlib.sha256).digest()

def zhash(msg):
    return int.from_bytes(hashlib.sha256(msg).digest()[:16],"big")%N

def sign(d,msg):
    z=zhash(msg); k=det_nonce(d,z)
    x=mul(k,G)[0]%N
    r=x
    s=inv(k,N)*(z+r*d)%N
    return r,s,z,k

def verify(Q,msg,r,s):
    z=zhash(msg)
    if not (0<r<N and 0<s<N): return False
    w=inv(s,N)
    u1=z*w%N; u2=r*w%N
    Pt=add(mul(u1,G),mul(u2,Q))
    if Pt is None: return False
    return Pt[0]%N==r
