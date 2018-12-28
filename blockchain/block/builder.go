// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package block

import (
	"github.com/pkg/errors"

	"github.com/iotexproject/iotex-core/action"
	"github.com/iotexproject/iotex-core/crypto"
	"github.com/iotexproject/iotex-core/iotxaddress"
	"github.com/iotexproject/iotex-core/pkg/hash"
	"github.com/iotexproject/iotex-core/pkg/version"
)

// Builder is used to construct Block.
type Builder struct{ blk Block }

// NewBuilder creates a Builder.
func NewBuilder() *Builder {
	return &Builder{
		blk: Block{
			Header: &Header{
				version: version.ProtocolVersion,
			},
		},
	}
}

// SetVersion sets the protocol version for block which is building.
func (b *Builder) SetVersion(v uint32) *Builder {
	b.blk.Header.version = v
	return b
}

// SetChainID sets the chain id for block which is building.
func (b *Builder) SetChainID(c uint32) *Builder {
	b.blk.Header.chainID = c
	return b
}

// SetHeight sets the block height for block which is building.
func (b *Builder) SetHeight(h uint64) *Builder {
	b.blk.Header.height = h
	return b
}

// SetTimeStamp sets the time stamp for block which is building.
func (b *Builder) SetTimeStamp(ts uint64) *Builder {
	b.blk.Header.timestamp = ts
	return b
}

// SetPrevBlockHash sets the previous block hash for block which is building.
func (b *Builder) SetPrevBlockHash(h hash.Hash32B) *Builder {
	b.blk.Header.prevBlockHash = h
	return b
}

// AddActions adds actions for block which is building.
func (b *Builder) AddActions(acts ...action.SealedEnvelope) *Builder {
	if b.blk.Actions == nil {
		b.blk.Actions = make([]action.SealedEnvelope, 0)
	}
	b.blk.Actions = append(b.blk.Actions, acts...)
	return b
}

// SetStateRoot sets the new state root after running actions included in this building block.
func (b *Builder) SetStateRoot(h hash.Hash32B) *Builder {
	b.blk.Header.stateRoot = h
	return b
}

// SetReceipts sets the receipts after running actions included in this building block.
func (b *Builder) SetReceipts(rm map[hash.Hash32B]*action.Receipt) *Builder {
	b.blk.Receipts = make(map[hash.Hash32B]*action.Receipt)
	for h, r := range rm {
		b.blk.Receipts[h] = r
	}
	return b
}

// SetSecretProposals sets the secret proposals for block which is building.
func (b *Builder) SetSecretProposals(sp []*action.SecretProposal) *Builder {
	b.blk.SecretProposals = sp
	return b
}

// SetSecretWitness sets the secret witness for block which is building.
func (b *Builder) SetSecretWitness(sw *action.SecretWitness) *Builder {
	b.blk.SecretWitness = sw
	return b
}

// SetDKG sets the DKG parts for block which is building.
func (b *Builder) SetDKG(id, pk, sig []byte) *Builder {
	b.blk.Header.dkgID = id
	b.blk.Header.dkgPubkey = pk
	b.blk.Header.dkgBlockSig = sig
	return b
}

// RunnableActions abstructs data to run actions.
func (b *Builder) RunnableActions(signer *iotxaddress.Address) RunnableActions {
	return RunnableActions{
		BlockHeight:         b.blk.Header.height,
		BlockHash:           b.blk.HashBlock(),
		BlockTimeStamp:      b.blk.Header.timestamp,
		BlockProducerPubKey: signer.PublicKey,
		BlockProducerAddr:   signer.RawAddress,
		Actions:             b.blk.Actions,
	}
}

// SignAndBuild signs and then builds a block.
func (b *Builder) SignAndBuild(signer *iotxaddress.Address) (Block, error) {
	b.blk.Header.txRoot = b.blk.CalculateTxRoot()
	b.blk.Header.pubkey = signer.PublicKey
	blkHash := b.blk.HashBlock()
	sig := crypto.EC283.Sign(signer.PrivateKey, blkHash[:])
	if len(sig) == 0 {
		return Block{}, errors.New("Failed to sign block")
	}
	b.blk.Header.blockSig = sig
	return b.blk, nil
}
