// Deliberately insecure demo: a private key validated with big.Int, whose timing depends on the key.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
)

func Save(key *ecdsa.PrivateKey) ([]byte, error) {
	if key.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, fmt.Errorf("invalid private key")
	}
	return key.D.FillBytes(make([]byte, 32)), nil
}
