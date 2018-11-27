# crypto

crypto is a cryptography library used in NKN.

## Usage

import "github.com/nknorg/crypto"

### Digest

* SHA256

```
	SHA256.Hash(value []byte) []byte
```

* SHA3_256

```
	SHA3_256.Hash(value []byte) []byte
```

* RIPEMD160

```
	RIPEMD160.Hash(value []byte) []byte
```

### Cipher

* AES-CBC

```
   ToAesKey(pwd []byte) []byte
   AesEncrypt(plaintext []byte, key []byte, iv []byte)  ([]byte, error)
   AesDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error)
```

### Signature

* Generate Key

```
	// ECDSA(p256r1)
	P256R1.New() (*Keypair, error)
	// ED25519
	ED25519.New() (*Keypair, error)
```

* Sign & Verify

```
	type PubKey interface {
		EqualTo(pk PubKey) bool
		Compress(isCommpressed bool) ([]byte, error)
		DeCompress(encodeData []byte) error
		Marshal() ([]byte, error)
		Unmarshal(data []byte) error
		Verify(data []byte, signature []byte) error
	}

	type PrivKey interface {
		PublicKey() PubKey
		Marshal() ([]byte, error)
		Unmarshal(data []byte) error
		Sign(data []byte) ([]byte, error)
	}

	type Keypair struct {
		pk PubKey
		sk PrivKey
	}
```

### Random number

```
	RandBytes(b []byte) (n int, err error)
```

### License

crypto is under APACHE-2.0 license. See LICENSE for details.
