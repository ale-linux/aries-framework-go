/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub_test

import (
	"testing"

	ml "github.com/IBM/mathlib"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlindSignMessages(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	blindMsgCount := 2

	messagesBytes := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
		[]byte("message4"),
	}

	blindedMessagesBytes := [][]byte{
		[]byte("message1"),
		nil,
		nil,
		[]byte("message4"),
	}

	clearMessagesBytes := [][]byte{
		nil,
		[]byte("message2"),
		[]byte("message3"),
		nil,
	}

	blindedMessagesBitmap := []bool{
		true,
		false,
		false,
		true,
	}

	bm, err := bbs12381g2pub.BlindMessages(blindedMessagesBytes, pubKey, blindMsgCount, []byte("nonce578"))
	assert.NoError(t, err)

	S := bm.S

	bmBytes := bm.Bytes()
	bm, err = bbs12381g2pub.ParseBlindedMessages(bmBytes)
	assert.NoError(t, err)

	err = bbs12381g2pub.VerifyBlinding(blindedMessagesBitmap, bm.C, bm.PoK, pubKey, []byte("nonce578"))
	assert.NoError(t, err)

	bls := bbs12381g2pub.New()

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	signatureBytes, err := bls.BlindSign(clearMessagesBytes, bm.C, privKeyBytes)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	signatureBytes, err = bls.UnblindSign(signatureBytes, S)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))
}

func TestBlindSignZr(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	blindMsgCount := 1

	rnd, err := ml.Curves[ml.BLS12_381_BBS].Rand()
	require.NoError(t, err)
	zr := ml.Curves[ml.BLS12_381_BBS].NewRandomZr(rnd)

	blindedMessagesZr := []*ml.Zr{
		zr,
		nil,
	}

	clearMessagesBytes := [][]byte{
		nil,
		[]byte("message2"),
	}

	blindedMessagesBitmap := []bool{
		true,
		false,
	}

	bm, err := bbs12381g2pub.BlindMessagesZr(blindedMessagesZr, pubKey, blindMsgCount, []byte("nonce23423"))
	assert.NoError(t, err)

	err = bbs12381g2pub.VerifyBlinding(blindedMessagesBitmap, bm.C, bm.PoK, pubKey, []byte("nonce23423"))
	assert.NoError(t, err)

	bls := bbs12381g2pub.New()

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	signatureBytes, err := bls.BlindSign(clearMessagesBytes, bm.C, privKeyBytes)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	signatureBytes, err = bls.UnblindSign(signatureBytes, bm.S)
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	signature, err := bbs12381g2pub.ParseSignature(signatureBytes)
	require.NoError(t, err)

	messagesCount := 2

	publicKeyWithGenerators, err := pubKey.ToPublicKeyWithGenerators(messagesCount)
	require.NoError(t, err)

	messagesZr := []*bbs12381g2pub.SignatureMessage{
		{FR: zr, Idx: 0},
		{FR: bbs12381g2pub.FrFromOKM(clearMessagesBytes[1]), Idx: 1},
	}

	err = signature.Verify(messagesZr, publicKeyWithGenerators)
	require.NoError(t, err)
}
