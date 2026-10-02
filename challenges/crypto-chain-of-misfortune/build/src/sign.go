package main

// ECDSA over P-256 (stdlib). The verifier accepts BOTH s and n-s (no low-s
// enforcement) — exactly as on-chain ecrecover does in the real world. The
// dedup/anti-doublespend layer keys on the signature *bytes*, so (r, n-s) is a
// second, distinct redemption of the same authorised action (malleability).
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

var curve = elliptic.P256()

// order N of the curve (public constant; players need it to compute n-s).
func curveN() *big.Int { return curve.Params().N }

func privFromD(d *big.Int) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return priv
}

func pubFromXY(x, y *big.Int) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
}

func sign(priv *ecdsa.PrivateKey, dig []byte) (r, s *big.Int) {
	r, s, err := ecdsa.Sign(rand.Reader, priv, dig)
	if err != nil {
		panic(err)
	}
	return r, s
}

// verify returns true for any valid (r, s) with 0<r,s<N — including the malleable
// high-s counterpart n-s of a canonical signature.
func verify(pub *ecdsa.PublicKey, dig []byte, r, s *big.Int) bool {
	n := curveN()
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	return ecdsa.Verify(pub, dig, r, s)
}
