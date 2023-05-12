/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub_test

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlindSign(t *testing.T) {
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

	bm, err := bbs12381g2pub.BlindMessages(blindedMessagesBytes, pubKey, blindMsgCount)
	assert.NoError(t, err)

	err = bbs12381g2pub.VerifyBlinding(blindedMessagesBitmap, bm.C, bm.PoK, pubKey)
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

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))
}
