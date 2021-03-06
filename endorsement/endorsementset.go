// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package endorsement

import (
	"bytes"

	"github.com/pkg/errors"

	"github.com/iotexproject/iotex-core/proto"
)

var (
	// ErrExpiredEndorsement indicates that the endorsement is from previous rounds
	ErrExpiredEndorsement = errors.New("the endorsement is from previous round")
	// ErrInvalidHash indicates that the endorsement hash is different from the set
	ErrInvalidHash = errors.New("the endorsement hash is different from the set")
	// ErrInvalidEndorsement indicates that the signature of the endorsement is invalid
	ErrInvalidEndorsement = errors.New("the endorsement's signature is invalid")
)

// Set is a collection of endorsements for block
type Set struct {
	blkHash      []byte
	round        uint32 // locked round number
	endorsements []*Endorsement
}

// NewSet creates an endorsement set
func NewSet(blkHash []byte) *Set {
	return &Set{
		blkHash:      blkHash,
		endorsements: []*Endorsement{},
	}
}

// FromProto converts protobuf to endorsement set
func (s *Set) FromProto(sPb *iproto.EndorsementSet) error {
	s.blkHash = sPb.BlockHash
	s.round = sPb.Round
	s.endorsements = []*Endorsement{}
	for _, ePb := range sPb.Endorsements {
		en, err := FromProtoMsg(ePb)
		if err != nil {
			return err
		}
		s.endorsements = append(s.endorsements, en)
	}

	return nil
}

// AddEndorsement adds an endorsement with the right block hash and signature
func (s *Set) AddEndorsement(en *Endorsement) error {
	if !bytes.Equal(en.ConsensusVote().BlkHash, s.blkHash) {
		return ErrInvalidHash
	}
	if !en.VerifySignature() {
		return ErrInvalidEndorsement
	}
	for i, e := range s.endorsements {
		if e.Endorser() != en.Endorser() {
			continue
		}
		if e.ConsensusVote().Topic != en.ConsensusVote().Topic {
			continue
		}
		if e.ConsensusVote().Round < en.ConsensusVote().Round {
			s.endorsements[i] = en
			return nil
		}
		return ErrExpiredEndorsement
	}
	s.endorsements = append(s.endorsements, en)

	return nil
}

// BlockHash returns the hash of the endorsed block
func (s *Set) BlockHash() []byte {
	return s.blkHash
}

// Round returns the locked round number
func (s *Set) Round() uint32 {
	return s.round
}

// SetRound sets the locked round number
func (s *Set) SetRound(round uint32) {
	s.round = round
}

// NumOfValidEndorsements returns the number of endorsements of the given topics and the endorsers
func (s *Set) NumOfValidEndorsements(topics map[ConsensusVoteTopic]bool, endorsers []string) int {
	endorserSet := map[string]bool{}
	for _, endorser := range endorsers {
		endorserSet[endorser] = true
	}
	cnt := 0
	for _, endorsement := range s.endorsements {
		if _, ok := topics[endorsement.ConsensusVote().Topic]; !ok {
			continue
		}
		if _, ok := endorserSet[endorsement.endorser]; !ok {
			continue
		}
		delete(endorserSet, endorsement.endorser)
		cnt++
	}

	return cnt
}

// ToProto convert the endorsement set to protobuf
func (s *Set) ToProto() *iproto.EndorsementSet {
	endorsements := make([]*iproto.EndorsePb, 0, len(s.endorsements))
	for _, en := range s.endorsements {
		endorsements = append(endorsements, en.ToProtoMsg())
	}

	return &iproto.EndorsementSet{
		BlockHash:    s.blkHash[:],
		Round:        s.round,
		Endorsements: endorsements,
	}
}
