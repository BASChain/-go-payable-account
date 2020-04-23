package account

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"
	"github.com/BASChain/go-account/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/scrypt"
)

var KP = struct {
	S int
	N int
	R int
	P int
	L int
}{
	S: 8,
	N: 1 << 15,
	R: 8,
	P: 1,
	L: 32,
}
var (
	EConvertCurvePubKey = fmt.Errorf("convert ed25519 public key to curve25519 public key failed")
)

type PipeCryptKey [32]byte

func AESKey(salt []byte, password string) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, KP.N, KP.R, KP.P, KP.L)
}

func GenerateAesKey(peerPub []byte, key ed25519.PrivateKey) ([]byte, error) {
	var priKey [32]byte
	var privateKeyBytes [64]byte
	copy(privateKeyBytes[:], key)
	PrivateKeyToCurve25519(&priKey, &privateKeyBytes)

	var curvePub, pubKey [32]byte
	copy(pubKey[:], peerPub)
	if ok := PublicKeyToCurve25519(&curvePub, &pubKey); !ok {
		return nil, EConvertCurvePubKey
	}
	return curve25519.X25519(priKey[:], curvePub[:])
}

func populateKey(data []byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	pri := ed25519.PrivateKey(data)
	pub := pri.Public().(ed25519.PublicKey)
	return pub, pri
}

func PrivateKeyToCurve25519(curve25519Private *[32]byte, privateKey *[64]byte) {
	h := sha512.New()
	h.Write(privateKey[:32])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	copy(curve25519Private[:], digest)
}

func edwardsToMontgomeryX(outX, y *edwards25519.FieldElement) {
	var oneMinusY edwards25519.FieldElement
	edwards25519.FeOne(&oneMinusY)
	edwards25519.FeSub(&oneMinusY, &oneMinusY, y)
	edwards25519.FeInvert(&oneMinusY, &oneMinusY)

	edwards25519.FeOne(outX)
	edwards25519.FeAdd(outX, outX, y)

	edwards25519.FeMul(outX, outX, &oneMinusY)
}

func PublicKeyToCurve25519(curve25519Public *[32]byte, publicKey *[32]byte) bool {
	var A edwards25519.ExtendedGroupElement
	if !A.FromBytes(publicKey) {
		return false
	}

	var x edwards25519.FieldElement
	edwardsToMontgomeryX(&x, &A.Y)
	edwards25519.FeToBytes(curve25519Public, &x)
	return true
}
