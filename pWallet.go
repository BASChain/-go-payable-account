package account

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pborman/uuid"
	"io/ioutil"
)

const (
	WalletVersion = 1
)

type WalletKey struct {
	SubPriKey  ed25519.PrivateKey
	MainPriKey *ecdsa.PrivateKey
}

type PayableWallet struct {
	Version   int                 `json:"version"`
	MainAddr  common.Address      `json:"mainAddress"`
	Crypto    keystore.CryptoJSON `json:"crypto"`
	SubAddr   ID                  `json:"subAddress"`
	SubCipher string              `json:"subCipher"`
	key       *WalletKey          `json:"-"`
}

func NewPayableWallet(auth string) (Wallet, error) {
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
	cipherTxt, err := EncryptSubPriKey(pri, pub, auth)
	if err != nil {
		return nil, err
	}

	obj := &PayableWallet{
		Version:   WalletVersion,
		MainAddr:  crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		SubAddr:   ToIDByBytes(pub),
		Crypto:    cryptoStruct,
		SubCipher: cipherTxt,
		key: &WalletKey{
			SubPriKey:  pri,
			MainPriKey: privateKeyECDSA,
		},
	}
	return obj, nil
}

func (pw *PayableWallet) SignKey() *ecdsa.PrivateKey {
	return pw.key.MainPriKey
}

func (pw *PayableWallet) MainAddress() common.Address {
	return pw.MainAddr
}
func (pw *PayableWallet) SubAddress() ID {
	return pw.SubAddr
}

func (pw *PayableWallet) SignJson(v interface{}) ([]byte, error) {
	rawBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	hash := crypto.Keccak256(rawBytes)
	return crypto.Sign(hash, pw.key.MainPriKey)
}

func (pw *PayableWallet) Sign(v []byte) ([]byte, error) {
	return crypto.Sign(v, pw.key.MainPriKey)
}

func (pw *PayableWallet) CryptKey() ed25519.PrivateKey {
	return pw.key.SubPriKey
}

func (pw *PayableWallet) SignJSONSub(v interface{}) []byte {
	rawBytes, _ := json.Marshal(v)
	return ed25519.Sign(pw.key.SubPriKey, rawBytes)
}

func (pw *PayableWallet) SignSub(v []byte) []byte {
	return ed25519.Sign(pw.key.SubPriKey, v)
}

func (pw *PayableWallet) IsOpen() bool {
	return pw.key != nil
}

func (pw *PayableWallet) SaveToPath(wPath string) error {
	bytes, err := json.MarshalIndent(pw, "", "\t")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(wPath, bytes, 0644)
}

func (pw *PayableWallet) Open(auth string) error {
	if pw.key != nil {
		return fmt.Errorf("wallet already opened")
	}

	keyBytes, err := keystore.DecryptDataV3(pw.Crypto, auth)
	if err != nil {
		return err
	}
	subKey, err := DecryptSubPriKey(pw.SubAddr.ToPubKey(), pw.SubCipher, auth)
	if err != nil {
		return err
	}
	key := &WalletKey{
		SubPriKey:  subKey,
		MainPriKey: crypto.ToECDSAUnsafe(keyBytes),
	}
	pw.key = key
	return nil
}

func (pw *PayableWallet) Close() {
	pw.key = nil
}

func (pw *PayableWallet) String() string {
	b, e := json.Marshal(pw)
	if e != nil {
		return ""
	}
	return string(b)
}

func (pw *PayableWallet) ExportEth(auth, eAuth, path string) error {

	keyBytes, err := keystore.DecryptDataV3(pw.Crypto, auth)
	if err != nil {
		panic(err)
	}
	key := crypto.ToECDSAUnsafe(keyBytes)

	ethKey := &keystore.Key{
		Address:    crypto.PubkeyToAddress(key.PublicKey),
		PrivateKey: key,
	}

	id := uuid.NewRandom()
	ethKey.Id = make([]byte, len(id))
	copy(ethKey.Id, id)

	newJson, err := keystore.EncryptKey(ethKey, eAuth, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		return fmt.Errorf("error encrypting with new password: %v", err)
	}
	if err := ioutil.WriteFile(path, newJson, 0644); err != nil {
		return fmt.Errorf("error writing new keyfile to disk: %v", err)
	}
	return nil
}
