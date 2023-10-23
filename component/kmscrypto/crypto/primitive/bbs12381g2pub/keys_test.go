/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	math "github.com/IBM/mathlib"
	b "github.com/ale-linux/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	h := sha256.New

	seed := make([]byte, 32)

	bbs := b.NewBBSLib(math.Curves[math.BLS12_381_BBS])

	pubKey, privKey, err := bbs.GenerateKeyPair(h, seed)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.NotNil(t, privKey)

	// use random seed
	pubKey, privKey, err = bbs.GenerateKeyPair(h, nil)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.NotNil(t, privKey)

	// invalid size of seed
	pubKey, privKey, err = bbs.GenerateKeyPair(h, make([]byte, 31))
	require.Error(t, err)
	require.EqualError(t, err, "invalid size of seed")
	require.Nil(t, pubKey)
	require.Nil(t, privKey)
}

func TestPrivateKey_Marshal(t *testing.T) {
	_, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)
	require.NotNil(t, privKeyBytes)

	bbs := b.NewBBSLib(math.Curves[math.BLS12_381_BBS])

	privKeyUnmarshalled, err := bbs.UnmarshalPrivateKey(privKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, privKeyUnmarshalled)
	require.Equal(t, privKey, privKeyUnmarshalled)
}

func TestPrivateKey_PublicKey(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	require.Equal(t, pubKey, privKey.PublicKey())
}

func TestPublicKey_Marshal(t *testing.T) {
	pubKey, _, err := generateKeyPairRandom()
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)
	require.NotNil(t, pubKeyBytes)

	bbs := b.NewBBSLib(math.Curves[math.BLS12_381_BBS])

	pubKeyUnmarshalled, err := bbs.UnmarshalPublicKey(pubKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, pubKeyUnmarshalled)
	require.True(t, pubKey.PointG2.Equals(pubKeyUnmarshalled.PointG2))
}

func TestParseMattrKeys(t *testing.T) {
	privKeyB58 := "5D6Pa8dSwApdnfg7EZR8WnGfvLDCZPZGsZ5Y1ELL9VDj"
	privKeyBytes := base58.Decode(privKeyB58)

	pubKeyB58 := "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu" //nolint:lll
	pubKeyBytes := base58.Decode(pubKeyB58)

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}
	signatureBytes, err := b.New(math.Curves[math.BLS12_381_BBS]).Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)

	err = b.New(math.Curves[math.BLS12_381_BBS]).Verify(messagesBytes, signatureBytes, pubKeyBytes)
	require.NoError(t, err)
}

func generateKeyPairRandom() (*b.PublicKey, *b.PrivateKey, error) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	bbs := b.NewBBSLib(math.Curves[math.BLS12_381_BBS])

	return bbs.GenerateKeyPair(sha256.New, seed)
}
