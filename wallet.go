package account

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type Wallet interface {
	SignKey() *ecdsa.PrivateKey
	CryptKey() ed25519.PrivateKey

	MainAddress() common.Address
	SubAddress() ID

	SignJson(v interface{}) ([]byte, error)
	Sign(v []byte) ([]byte, error)
	SignJSONSub(v interface{}) []byte
	SignSub(v []byte) []byte

	Open(auth string) error
	IsOpen() bool
	SaveToPath(wPath string) error
	String() string
	Close()
	ExportEth(auth, eAuth, path string) error
}

func encryptSubPriKey(priKey ed25519.PrivateKey, pubKey ed25519.PublicKey, auth string) (string, error) {
	aesKey, err := AESKey(pubKey[:KP.S], auth)
	if err != nil {
		return "", err
	}
	cipher, err := Encrypt(aesKey, priKey[:])
	if err != nil {
		return "", err
	}
	return base58.Encode(cipher), nil
}

func decryptSubPriKey(subPub ID, cpTxt, auth string) (ed25519.PrivateKey, error) {
	pk := subPub.ToPubKey()
	aesKey, err := AESKey(pk[:KP.S], auth)
	if err != nil {
		return nil, err
	}
	cipherByte := base58.Decode(cpTxt)
	subKey := make([]byte, len(cipherByte))
	copy(subKey, cipherByte)
	return Decrypt(aesKey, subKey)
}

func VerifyJsonSig(mainAddr common.Address, sig []byte, v interface{}) bool {
	return mainAddr == RecoverJson(sig, v)
}

func VerifyAbiSig(mainAddr common.Address, sig []byte, msg []byte) bool {
	signer, err := crypto.SigToPub(msg, sig)
	if err != nil {
		return false
	}

	return mainAddr == crypto.PubkeyToAddress(*signer)
}

func RecoverJson(sig []byte, v interface{}) common.Address {
	data, err := json.Marshal(v)
	if err != nil {
		return common.Address{}
	}
	hash := crypto.Keccak256(data)
	signer, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return common.Address{}
	}
	address := crypto.PubkeyToAddress(*signer)
	return address
}

func VerifySubSig(subAddr ID, sig []byte, v interface{}) bool {
	data, err := json.Marshal(v)
	if err != nil {
		return false
	}

	return ed25519.Verify(subAddr.ToPubKey(), data, sig)
}
