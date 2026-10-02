package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "selftest" {
		selftest()
		return
	}
	serve()
}

// selftest validates the crypto invariants the challenge relies on, independent
// of any instance file: legacy-domain cross-chain replay, modern-domain binding,
// and ECDSA s-malleability acceptance.
func selftest() {
	name, ver := "NovaFest Tickets", "1"
	contract := make([]byte, 20)
	rand.Read(contract)
	mainID, testID := big.NewInt(8899), big.NewInt(11155)

	legacyMain := domainSeparator(name, ver, mainID, contract, false)
	legacyTest := domainSeparator(name, ver, testID, contract, false)
	modernMain := domainSeparator(name, ver, mainID, contract, true)
	modernTest := domainSeparator(name, ver, testID, contract, true)

	eq := func(a, b []byte) bool { return string(a) == string(b) }
	fmt.Printf("legacy domain equal across chains (replayable): %v\n", eq(legacyMain, legacyTest))
	fmt.Printf("modern domain differs across chains (bound):     %v\n", !eq(modernMain, modernTest))

	// a signed legacy ticket verifies on both chains
	d, _ := rand.Int(rand.Reader, curveN())
	priv := privFromD(d)
	holder := make([]byte, 20)
	rand.Read(holder)
	sh := hashTicket(big.NewInt(1), holder, "ADMIT", big.NewInt(1))
	digMain := digest(legacyMain, sh)
	digTest := digest(legacyTest, sh)
	r, s := sign(priv, digTest)
	fmt.Printf("legacy sig valid on test:  %v\n", verify(&priv.PublicKey, digTest, r, s))
	fmt.Printf("legacy sig REPLAYS to main: %v\n", verify(&priv.PublicKey, digMain, r, s))

	// malleability: (r, N-s) also verifies but is different bytes
	sMall := new(big.Int).Sub(curveN(), s)
	fmt.Printf("malleable (r, N-s) valid:   %v  (distinct bytes: %v)\n",
		verify(&priv.PublicKey, digMain, r, sMall), sMall.Cmp(s) != 0)

	ok := eq(legacyMain, legacyTest) && !eq(modernMain, modernTest) &&
		verify(&priv.PublicKey, digMain, r, s) && verify(&priv.PublicKey, digMain, r, sMall)
	if !ok {
		fmt.Println("SELFTEST FAILED")
		os.Exit(1)
	}
	fmt.Println("SELFTEST OK")
}
