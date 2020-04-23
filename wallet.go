package account

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"io/ioutil"
)

const (
	WalletVersion = 1
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

type WalletKey struct {
	SubPriKey  ed25519.PrivateKey
	MainPriKey *ecdsa.PrivateKey
}

type PWallet struct {
	Version   int                 `json:"version"`
	MainAddr  common.Address      `json:"mainAddress"`
	Crypto    keystore.CryptoJSON `json:"crypto"`
	SubAddr   ID                  `json:"subAddress"`
	SubCipher string              `json:"subCipher"`
	key       *WalletKey          `json:"-"`
}

func NewWallet(auth string) (Wallet, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes := math.PaddedBigBytes(privateKeyECDSA.D, 32)
	cryptoStruct, err := keystore.EncryptDataV3(keyBytes, []byte(auth), keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		return nil, err
	}

	pub, pri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cipherTxt, err := encryptSubPriKey(pri, pub, auth)
	if err != nil {
		return nil, err
	}

	obj := &PWallet{
		Version:   WalletVersion,
		MainAddr:  crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		SubAddr:   ConvertToID2(pub),
		Crypto:    cryptoStruct,
		SubCipher: cipherTxt,
		key: &WalletKey{
			SubPriKey:  pri,
			MainPriKey: privateKeyECDSA,
		},
	}
	return obj, nil
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

func LoadWallet(wPath string) (Wallet, error) {
	jsonStr, err := ioutil.ReadFile(wPath)
	if err != nil {
		return nil, err
	}

	w := new(PWallet)
	if err := json.Unmarshal(jsonStr, w); err != nil {
		return nil, err
	}
	return w, nil
}

func LoadWalletByData(jsonStr string) (Wallet, error) {
	w := new(PWallet)
	if err := json.Unmarshal([]byte(jsonStr), w); err != nil {
		return nil, err
	}
	return w, nil
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
