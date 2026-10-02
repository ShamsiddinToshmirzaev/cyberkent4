package main

// EIP-712-style typed-data hashing for the NovaFest "EVM-like" testnet.
//
// This mirrors real EIP-712 structure (typeHash, encodeData, domainSeparator,
// 0x19 0x01 digest) but uses SHA-256 as the hash and P-256 as the curve so the
// challenge is self-contained (no external deps). The BUG is faithful to the real
// world: the *legacy* ticket domain omits chainId, so its domain separator is
// identical on every chain and a signature replays across chains (EIP-712 itself
// states it provides no replay protection; binding chainId is the app's job).
import (
	"crypto/sha256"
	"math/big"
)

func h(parts ...[]byte) []byte {
	s := sha256.New()
	for _, p := range parts {
		s.Write(p)
	}
	return s.Sum(nil)
}

// 32-byte big-endian encoding of a uint256.
func word(x *big.Int) []byte {
	b := x.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// 20-byte address, left-padded to a 32-byte word.
func addrWord(addr []byte) []byte {
	out := make([]byte, 32)
	if len(addr) <= 20 {
		copy(out[32-len(addr):], addr)
	} else {
		copy(out[12:], addr[len(addr)-20:])
	}
	return out
}

const (
	legacyDomainType = "EIP712Domain(string name,string version,address verifyingContract)"
	modernDomainType = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
	ticketType       = "Ticket(uint256 ticketId,address holder,string action,uint256 tier)"
)

// domainSeparator: the legacy variant deliberately omits chainId, so it is the
// same on MainStage and TestStage (verifyingContract is the same address on both
// chains, as with a CREATE2 deployment) => cross-chain replay.
func domainSeparator(name, version string, chainID *big.Int, contract []byte, includeChainID bool) []byte {
	if includeChainID {
		return h(h([]byte(modernDomainType)),
			h([]byte(name)), h([]byte(version)), word(chainID), addrWord(contract))
	}
	return h(h([]byte(legacyDomainType)),
		h([]byte(name)), h([]byte(version)), addrWord(contract))
}

func hashTicket(ticketID *big.Int, holder []byte, action string, tier *big.Int) []byte {
	return h(h([]byte(ticketType)),
		word(ticketID), addrWord(holder), h([]byte(action)), word(tier))
}

// digest = SHA256( 0x19 0x01 || domainSeparator || hashStruct(message) )
func digest(domainSep, structHash []byte) []byte {
	return h([]byte{0x19, 0x01}, domainSep, structHash)
}
