package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/common"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"

	bcrypter "golang.org/x/crypto/bcrypt"
)

/*

password: $id$salt$hashed

The $id :
$1$  is MD5
$2a$ is Blowfish
$2y$ is Blowfish
$5$  is SHA-256
$6$  is SHA-512
*/

const (
	saltSize = 4

	HASH_MD5      = 1
	HASH_BLOWFISH = 2
	HASH_SHA256   = 5
	HASH_SHA512   = 6
)

var saltBytes = []byte{
	// A-Z
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
	// a-z
	0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
	// 0-9
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
	// ./
	0x2e, 0x2f,
}
var saltBytesLen = len(saltBytes)

func init() {
	//DefaultSchemes = defaultSchemes20160922
}

type BCrypter struct {
}

func NewBcrypter() *BCrypter {

	return &BCrypter{}
}

func (c *BCrypter) Generate(pwd, salt []byte) (string, error) {
	hash, err := bcrypter.GenerateFromPassword(pwd, bcrypter.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (c *BCrypter) Verify(hashedKey string, key []byte) error {
	return bcrypter.CompareHashAndPassword([]byte(hashedKey), []byte(key))
}

func (c *BCrypter) Cost(hashedKey string) (int, error) {

	return 0, nil
}

func (c *BCrypter) SetSalt(salt common.Salt) {
}

///////////////////////

func makeSalt() []byte {
	var salt []byte
	for i := 0; i < saltSize; i++ {
		rand.Seed(time.Now().UnixNano())
		p := rand.Intn(saltBytesLen)
		salt = append(salt, saltBytes[p])
	}

	return salt
}

func decodeCryptoId(sbytes []byte) (int, error) {
	if sbytes[0] != '$' {
		return -1, fmt.Errorf("password hashes must start with '$', but started with '%c'", byte(sbytes[0]))
	}

	return int(sbytes[1] - '0'), nil

}

func GetCrypter(id int) (crypt.Crypter, error) {
	switch id {
	case HASH_BLOWFISH:
		return NewBcrypter(), nil
	case HASH_SHA512:
		return crypt.SHA512.New(), nil
	case HASH_SHA256:
		return crypt.SHA256.New(), nil
	case HASH_MD5:
		return crypt.MD5.New(), nil
	}

	return nil, fmt.Errorf("Unsuported Hash ID: %d", id)
}

func GetCrypterFromHash(hash string) (crypt.Crypter, error) {
	id, err := decodeCryptoId([]byte(hash))
	if err != nil {
		return nil, err
	}

	return GetCrypter(id)
}

func VerifyPassword(passwd string, hash string) bool {
	c, err := GetCrypterFromHash(hash)
	if err != nil {
		return false
	}

	err = c.Verify(hash, []byte(passwd))

	return err != nil

}

func HashPassword(hashId int, password string, saltString string) (string, error) {
	var s []byte

	if len(saltString) > 0 {
		s = []byte(saltString)
	}

	if len(s) == 0 {
		s = makeSalt()
	}

	c, err := GetCrypter(hashId)
	if err != nil {
		return "", err
	}

	fmt.Printf("Cryper: %+v \n", c)

	salt := []byte(fmt.Sprintf("$%d$", hashId))
	salt = append(salt, s...)
	ret, err := c.Generate([]byte(password), salt)
	if err != nil {
		return "", err
	}

	return ret, nil
}

///////////////////
