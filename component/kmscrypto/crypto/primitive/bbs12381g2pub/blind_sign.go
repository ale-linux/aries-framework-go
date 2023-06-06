/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"errors"
	"fmt"

	ml "github.com/IBM/mathlib"
)

// BlindedMessages represents a set of messages prepared
// (blinded) to be submitted to a signer for a blind signature.
type BlindedMessages struct {
	PK  *PublicKeyWithGenerators
	S   *ml.Zr
	C   *ml.G1
	PoK *POKOfBlindedMessages
}

func (b *BlindedMessages) Bytes() []byte {
	bytes := make([]byte, 0)

	bytes = append(bytes, b.C.Compressed()...)
	bytes = append(bytes, b.PoK.C.Compressed()...)
	bytes = append(bytes, b.PoK.ProofC.ToBytes()...)

	return bytes
}

func ParseBlindedMessages(bytes []byte) (*BlindedMessages, error) {
	offset := 0

	C, err := curve.NewG1FromCompressed(bytes[offset : offset+g1CompressedSize])
	if err != nil {
		return nil, fmt.Errorf("parse G1 point (C): %w", err)
	}

	offset += g1CompressedSize

	PoKC, err := curve.NewG1FromCompressed(bytes[offset : offset+g1CompressedSize])
	if err != nil {
		return nil, fmt.Errorf("parse G1 point (PoKC): %w", err)
	}

	offset += g1CompressedSize

	proof, err := ParseProofG1(bytes[offset:])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}

	return &BlindedMessages{
		C: C,
		PoK: &POKOfBlindedMessages{
			C:      PoKC,
			ProofC: proof,
		},
	}, nil
}

// POKOfBlindedMessages is the zero-knowledge proof that the
// requester knows the messages they have submitted for blind
// signature in the form of a Pedersen commitment.
type POKOfBlindedMessages struct {
	C      *ml.G1
	ProofC *ProofG1
}

// VerifyProof verifies the correctness of the zero knowledge
// proof against the supplied commitment, challenge and public key.
func (b *POKOfBlindedMessages) VerifyProof(messages []bool, commitment *ml.G1, challenge *ml.Zr, PK *PublicKey) error {
	pubKeyWithGenerators, err := PK.ToPublicKeyWithGenerators(len(messages))
	if err != nil {
		return fmt.Errorf("build generators from public key: %w", err)
	}

	bases := []*ml.G1{pubKeyWithGenerators.H0}

	for i, in := range messages {
		if !in {
			continue
		}

		bases = append(bases, pubKeyWithGenerators.H[i])
	}

	err = b.ProofC.Verify(bases, commitment, challenge)
	if err != nil {
		return errors.New("invalid proof")
	}

	return nil
}

// VerifyBlinding verifies that `msgCommit` is a valid
// commitment of a set of messages against the appropriate bases.
func VerifyBlinding(messageBitmap []bool, msgCommit *ml.G1, bmProof *POKOfBlindedMessages, PK *PublicKey, nonce []byte) error {
	challengeBytes := msgCommit.Bytes()
	challengeBytes = append(challengeBytes, bmProof.C.Bytes()...)
	challengeBytes = append(challengeBytes, nonce...)

	return bmProof.VerifyProof(messageBitmap, msgCommit, FrFromOKM(challengeBytes), PK)
}

// BlindMessages constructs a commitment to a set of messages
// that need to be blinded before signing, and generates the
// corresponding ZKP.
func BlindMessages(messages [][]byte, PK *PublicKey, blindedMsgCount int, nonce []byte) (*BlindedMessages, error) {
	zrs := make([]*ml.Zr, len(messages))

	for i, msg := range messages {
		if len(msg) == 0 {
			continue
		}

		zrs[i] = FrFromOKM(msg)
	}

	return BlindMessagesZr(zrs, PK, blindedMsgCount, nonce)
}

// BlindMessagesZr constructs a commitment to a set of messages
// that need to be blinded before signing, and generates the
// corresponding ZKP.
func BlindMessagesZr(zrs []*ml.Zr, PK *PublicKey, blindedMsgCount int, nonce []byte) (*BlindedMessages, error) {
	pubKeyWithGenerators, err := PK.ToPublicKeyWithGenerators(len(zrs))
	if err != nil {
		return nil, fmt.Errorf("build generators from public key: %w", err)
	}

	commit := NewProverCommittingG1()
	cb := newCommitmentBuilder(blindedMsgCount + 1)
	secrets := make([]*ml.Zr, 0, blindedMsgCount+1)

	s := createRandSignatureFr()

	commit.Commit(pubKeyWithGenerators.H0)
	cb.add(pubKeyWithGenerators.H0, s)
	secrets = append(secrets, s)

	for i, zr := range zrs {
		if zr == nil {
			continue
		}

		commit.Commit(pubKeyWithGenerators.H[i])
		cb.add(pubKeyWithGenerators.H[i], zr)
		secrets = append(secrets, zr)
	}

	C := cb.build()
	U := commit.Finish()

	challengeBytes := C.Bytes()
	challengeBytes = append(challengeBytes, U.commitment.Bytes()...)
	challengeBytes = append(challengeBytes, nonce...)

	return &BlindedMessages{
		PK: pubKeyWithGenerators,
		S:  s,
		C:  C,
		PoK: &POKOfBlindedMessages{
			C:      U.commitment,
			ProofC: U.GenerateProof(FrFromOKM(challengeBytes), secrets),
		},
	}, nil
}
