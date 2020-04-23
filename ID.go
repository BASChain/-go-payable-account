package account

import (
	"crypto/ed25519"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"hash/fnv"
)

const (
	AccPrefix       = "BM"
	AccIDLen        = 40
	SocketPortInit  = 52000
	SocketPortRange = 12000
)

var (
	EInvalidID = fmt.Errorf("invalid ID")
)

type ID string

func (id ID) ToServerPort() uint16 {
	h := fnv.New32a()
	h.Write([]byte(id))
	sum := h.Sum32()
	return uint16(SocketPortInit + sum%SocketPortRange)
}

func (id ID) String() string {
	return string(id)
}

func (id ID) ToPubKey() ed25519.PublicKey {
	if len(id) <= len(AccPrefix) {
		return nil
	}
	ss := string(id[len(AccPrefix):])
	return base58.Decode(ss)
}

func (id ID) ToArray() [32]byte {
	if len(id) <= len(AccPrefix) {
		return [32]byte{}
	}
	ss := string(id[len(AccPrefix):])
	ssByte := base58.Decode(ss)

	var arr [32]byte
	copy(arr[:], ssByte[:32])
	return arr
}

func (id ID) IsValid() bool {
	if len(id) <= AccIDLen {
		return false
	}
	if id[:len(AccPrefix)] != AccPrefix {
		return false
	}
	if len(id.ToPubKey()) != ed25519.PublicKeySize {
		return false
	}
	return true
}

func ConvertToID(addr string) (ID, error) {
	id := ID(addr)
	if id.IsValid() {
		return id, nil
	}
	return "", EInvalidID
}

func ConvertToID2(key []byte) ID {
	return ID(AccPrefix + base58.Encode(key))
}
