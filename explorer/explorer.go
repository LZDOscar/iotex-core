// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package explorer

import (
	"encoding/hex"
	"math/big"
	"net"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/iotexproject/iotex-core/action"
	"github.com/iotexproject/iotex-core/action/protocol/multichain/mainchain"
	"github.com/iotexproject/iotex-core/actpool"
	"github.com/iotexproject/iotex-core/address"
	"github.com/iotexproject/iotex-core/blockchain"
	"github.com/iotexproject/iotex-core/config"
	"github.com/iotexproject/iotex-core/consensus"
	"github.com/iotexproject/iotex-core/dispatcher"
	"github.com/iotexproject/iotex-core/explorer/idl/explorer"
	"github.com/iotexproject/iotex-core/indexservice"
	"github.com/iotexproject/iotex-core/pkg/hash"
	"github.com/iotexproject/iotex-core/pkg/keypair"
	"github.com/iotexproject/iotex-core/pkg/log"
	"github.com/iotexproject/iotex-core/proto"
)

var (
	// ErrInternalServer indicates the internal server error
	ErrInternalServer = errors.New("internal server error")
	// ErrTransfer indicates the error of transfer
	ErrTransfer = errors.New("invalid transfer")
	// ErrVote indicates the error of vote
	ErrVote = errors.New("invalid vote")
	// ErrExecution indicates the error of execution
	ErrExecution = errors.New("invalid execution")
	// ErrReceipt indicates the error of receipt
	ErrReceipt = errors.New("invalid receipt")
	// ErrAction indicates the error of action
	ErrAction = errors.New("invalid action")
)

var (
	requestMtc = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iotex_explorer_request",
			Help: "IoTeX Explorer request counter.",
		},
		[]string{"method", "succeed"},
	)
)

func init() {
	prometheus.MustRegister(requestMtc)
}

type (
	// Broadcast sends a broadcast message to the whole network
	Broadcast func(chainID uint32, msg proto.Message) error
	// Neighbors returns the neighbors' addresses
	Neighbors func() []net.Addr
	// Self returns the self network address
	Self func() net.Addr
)

// Service provide api for user to query blockchain data
type Service struct {
	bc               blockchain.Blockchain
	c                consensus.Consensus
	dp               dispatcher.Dispatcher
	ap               actpool.ActPool
	gs               GasStation
	broadcastHandler Broadcast
	neighborsHandler Neighbors
	selfHandler      Self
	cfg              config.Explorer
	idx              *indexservice.Server
	// TODO: the way to make explorer to access the data model managed by main-chain protocol is hack. We need to
	// refactor the code later
	mainChain *mainchain.Protocol
}

// SetMainChainProtocol sets the main-chain side multi-chain protocol
func (exp *Service) SetMainChainProtocol(mainChain *mainchain.Protocol) { exp.mainChain = mainChain }

// GetBlockchainHeight returns the current blockchain tip height
func (exp *Service) GetBlockchainHeight() (int64, error) {
	tip := exp.bc.TipHeight()
	return int64(tip), nil
}

// GetAddressBalance returns the balance of an address
func (exp *Service) GetAddressBalance(address string) (string, error) {
	state, err := exp.bc.StateByAddr(address)
	if err != nil {
		return "", err
	}
	return state.Balance.String(), nil
}

// GetAddressDetails returns the properties of an address
func (exp *Service) GetAddressDetails(address string) (explorer.AddressDetails, error) {
	state, err := exp.bc.StateByAddr(address)
	if err != nil {
		return explorer.AddressDetails{}, err
	}
	pendingNonce, err := exp.ap.GetPendingNonce(address)
	if err != nil {
		return explorer.AddressDetails{}, err
	}
	details := explorer.AddressDetails{
		Address:      address,
		TotalBalance: state.Balance.String(),
		Nonce:        int64((*state).Nonce),
		PendingNonce: int64(pendingNonce),
		IsCandidate:  (*state).IsCandidate,
	}

	return details, nil
}

// GetLastTransfersByRange returns transfers in [-(offset+limit-1), -offset] from block
// with height startBlockHeight
func (exp *Service) GetLastTransfersByRange(startBlockHeight int64, offset int64, limit int64, showCoinBase bool) ([]explorer.Transfer, error) {
	var res []explorer.Transfer
	transferCount := int64(0)

	for height := startBlockHeight; height >= 0; height-- {
		var blkID string
		hash, err := exp.bc.GetHashByHeight(uint64(height))
		if err != nil {
			return []explorer.Transfer{}, err
		}
		blkID = hex.EncodeToString(hash[:])

		blk, err := exp.bc.GetBlockByHeight(uint64(height))
		if err != nil {
			return []explorer.Transfer{}, err
		}

		selps := make([]action.SealedEnvelope, 0)
		for _, selp := range blk.Actions {
			act := selp.Action()
			if _, ok := act.(*action.Transfer); ok {
				selps = append(selps, selp)
			}
		}

		for i := len(selps) - 1; i >= 0; i-- {
			act := selps[i].Action().(*action.Transfer)
			if showCoinBase || !act.IsCoinbase() {
				transferCount++
			}

			if transferCount <= offset {
				continue
			}

			// if showCoinBase is true, add coinbase transfers, else only put non-coinbase transfers
			if showCoinBase || !act.IsCoinbase() {
				if int64(len(res)) >= limit {
					return res, nil
				}

				explorerTransfer, err := convertTsfToExplorerTsf(selps[i], false)
				if err != nil {
					return []explorer.Transfer{}, errors.Wrapf(err,
						"failed to convert transfer %v to explorer's JSON transfer", selps[i])
				}
				explorerTransfer.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
				explorerTransfer.BlockID = blkID
				res = append(res, explorerTransfer)
			}
		}
	}

	return res, nil
}

// GetTransferByID returns transfer by transfer id
func (exp *Service) GetTransferByID(transferID string) (explorer.Transfer, error) {
	bytes, err := hex.DecodeString(transferID)
	if err != nil {
		return explorer.Transfer{}, err
	}
	var transferHash hash.Hash32B
	copy(transferHash[:], bytes)

	return getTransfer(exp.bc, exp.ap, transferHash, exp.idx, exp.cfg.UseRDS)
}

// GetTransfersByAddress returns all transfers associated with an address
func (exp *Service) GetTransfersByAddress(address string, offset int64, limit int64) ([]explorer.Transfer, error) {
	var res []explorer.Transfer
	var transfers []hash.Hash32B
	if exp.cfg.UseRDS {
		transferHistory, err := exp.idx.Indexer().GetTransferHistory(address)
		if err != nil {
			return []explorer.Transfer{}, err
		}
		transfers = append(transfers, transferHistory...)
	} else {
		transfersFromAddress, err := exp.bc.GetTransfersFromAddress(address)
		if err != nil {
			return []explorer.Transfer{}, err
		}

		transfersToAddress, err := exp.bc.GetTransfersToAddress(address)
		if err != nil {
			return []explorer.Transfer{}, err
		}

		transfersFromAddress = append(transfersFromAddress, transfersToAddress...)
		transfers = append(transfers, transfersFromAddress...)
	}

	for i, transferHash := range transfers {
		if int64(i) < offset {
			continue
		}

		if int64(len(res)) >= limit {
			break
		}

		explorerTransfer, err := getTransfer(exp.bc, exp.ap, transferHash, exp.idx, exp.cfg.UseRDS)
		if err != nil {
			return []explorer.Transfer{}, err
		}

		res = append(res, explorerTransfer)
	}

	return res, nil
}

// GetUnconfirmedTransfersByAddress returns all unconfirmed transfers in actpool associated with an address
func (exp *Service) GetUnconfirmedTransfersByAddress(address string, offset int64, limit int64) ([]explorer.Transfer, error) {
	res := make([]explorer.Transfer, 0)
	if _, err := exp.bc.StateByAddr(address); err != nil {
		return []explorer.Transfer{}, err
	}

	selps := exp.ap.GetUnconfirmedActs(address)
	tsfIndex := int64(0)
	for _, selp := range selps {
		act := selp.Action()
		transfer, ok := act.(*action.Transfer)
		if !ok {
			continue
		}

		if tsfIndex < offset {
			tsfIndex++
			continue
		}

		if int64(len(res)) >= limit {
			break
		}

		explorerTransfer, err := convertTsfToExplorerTsf(selp, true)
		if err != nil {
			return []explorer.Transfer{}, errors.Wrapf(err, "failed to convert transfer %v to explorer's JSON transfer", transfer)
		}
		res = append(res, explorerTransfer)
	}

	return res, nil
}

// GetTransfersByBlockID returns transfers in a block
func (exp *Service) GetTransfersByBlockID(blkID string, offset int64, limit int64) ([]explorer.Transfer, error) {
	var res []explorer.Transfer
	bytes, err := hex.DecodeString(blkID)

	if err != nil {
		return []explorer.Transfer{}, err
	}
	var hash hash.Hash32B
	copy(hash[:], bytes)

	blk, err := exp.bc.GetBlockByHash(hash)
	if err != nil {
		return []explorer.Transfer{}, err
	}

	var num int
	for _, selp := range blk.Actions {
		if _, ok := selp.Action().(*action.Transfer); !ok {
			continue
		}
		if int64(num) < offset {
			continue
		}
		if int64(len(res)) >= limit {
			break
		}
		explorerTransfer, err := convertTsfToExplorerTsf(selp, false)
		if err != nil {
			return []explorer.Transfer{}, errors.Wrapf(err, "failed to convert transfer %v to explorer's JSON transfer", selp)
		}
		explorerTransfer.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
		explorerTransfer.BlockID = blkID
		res = append(res, explorerTransfer)
		num++
	}
	return res, nil
}

// GetLastVotesByRange returns votes in [-(offset+limit-1), -offset] from block
// with height startBlockHeight
func (exp *Service) GetLastVotesByRange(startBlockHeight int64, offset int64, limit int64) ([]explorer.Vote, error) {
	var res []explorer.Vote
	voteCount := uint64(0)

	for height := startBlockHeight; height >= 0; height-- {
		hash, err := exp.bc.GetHashByHeight(uint64(height))
		if err != nil {
			return []explorer.Vote{}, err
		}
		blkID := hex.EncodeToString(hash[:])

		blk, err := exp.bc.GetBlockByHeight(uint64(height))
		if err != nil {
			return []explorer.Vote{}, err
		}

		selps := make([]action.SealedEnvelope, 0)
		for _, selp := range blk.Actions {
			act := selp.Action()
			if _, ok := act.(*action.Vote); ok {
				selps = append(selps, selp)
			}
		}

		for i := int64(len(selps) - 1); i >= 0; i-- {
			voteCount++

			if voteCount <= uint64(offset) {
				continue
			}

			if int64(len(res)) >= limit {
				return res, nil
			}

			explorerVote, err := convertVoteToExplorerVote(selps[i], false)
			if err != nil {
				return []explorer.Vote{}, errors.Wrapf(err, "failed to convert vote %v to explorer's JSON vote", selps[i])
			}
			explorerVote.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
			explorerVote.BlockID = blkID
			res = append(res, explorerVote)
		}
	}

	return res, nil
}

// GetVoteByID returns vote by vote id
func (exp *Service) GetVoteByID(voteID string) (explorer.Vote, error) {
	bytes, err := hex.DecodeString(voteID)
	if err != nil {
		return explorer.Vote{}, err
	}
	var voteHash hash.Hash32B
	copy(voteHash[:], bytes)

	return getVote(exp.bc, exp.ap, voteHash, exp.idx, exp.cfg.UseRDS)
}

// GetVotesByAddress returns all votes associated with an address
func (exp *Service) GetVotesByAddress(address string, offset int64, limit int64) ([]explorer.Vote, error) {
	var res []explorer.Vote
	var votes []hash.Hash32B
	if exp.cfg.UseRDS {
		voteHistory, err := exp.idx.Indexer().GetVoteHistory(address)
		if err != nil {
			return []explorer.Vote{}, err
		}
		votes = append(votes, voteHistory...)
	} else {
		votesFromAddress, err := exp.bc.GetVotesFromAddress(address)
		if err != nil {
			return []explorer.Vote{}, err
		}

		votesToAddress, err := exp.bc.GetVotesToAddress(address)
		if err != nil {
			return []explorer.Vote{}, err
		}

		votesFromAddress = append(votesFromAddress, votesToAddress...)
		votes = append(votes, votesFromAddress...)
	}

	for i, voteHash := range votes {
		if int64(i) < offset {
			continue
		}

		if int64(len(res)) >= limit {
			break
		}

		explorerVote, err := getVote(exp.bc, exp.ap, voteHash, exp.idx, exp.cfg.UseRDS)
		if err != nil {
			return []explorer.Vote{}, err
		}

		res = append(res, explorerVote)
	}

	return res, nil
}

// GetUnconfirmedVotesByAddress returns all unconfirmed votes in actpool associated with an address
func (exp *Service) GetUnconfirmedVotesByAddress(address string, offset int64, limit int64) ([]explorer.Vote, error) {
	res := make([]explorer.Vote, 0)
	if _, err := exp.bc.StateByAddr(address); err != nil {
		return []explorer.Vote{}, err
	}

	selps := exp.ap.GetUnconfirmedActs(address)
	voteIndex := int64(0)
	for _, selp := range selps {
		act := selp.Action()
		vote, ok := act.(*action.Vote)
		if !ok {
			continue
		}

		if voteIndex < offset {
			voteIndex++
			continue
		}

		if int64(len(res)) >= limit {
			break
		}

		explorerVote, err := convertVoteToExplorerVote(selp, true)
		if err != nil {
			return []explorer.Vote{}, errors.Wrapf(err, "failed to convert vote %v to explorer's JSON vote", vote)
		}
		res = append(res, explorerVote)
	}

	return res, nil
}

// GetVotesByBlockID returns votes in a block
func (exp *Service) GetVotesByBlockID(blkID string, offset int64, limit int64) ([]explorer.Vote, error) {
	var res []explorer.Vote
	bytes, err := hex.DecodeString(blkID)
	if err != nil {
		return []explorer.Vote{}, err
	}
	var hash hash.Hash32B
	copy(hash[:], bytes)

	blk, err := exp.bc.GetBlockByHash(hash)
	if err != nil {
		return []explorer.Vote{}, err
	}

	var num int
	for _, selp := range blk.Actions {
		if _, ok := selp.Action().(*action.Vote); !ok {
			continue
		}
		if int64(num) < offset {
			continue
		}

		if int64(len(res)) >= limit {
			break
		}

		explorerVote, err := convertVoteToExplorerVote(selp, false)
		if err != nil {
			return []explorer.Vote{}, errors.Wrapf(err, "failed to convert vote %v to explorer's JSON vote", selp)
		}
		explorerVote.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
		explorerVote.BlockID = blkID
		res = append(res, explorerVote)
		num++
	}
	return res, nil
}

// GetLastExecutionsByRange returns executions in [-(offset+limit-1), -offset] from block
// with height startBlockHeight
func (exp *Service) GetLastExecutionsByRange(startBlockHeight int64, offset int64, limit int64) ([]explorer.Execution, error) {
	var res []explorer.Execution
	executionCount := uint64(0)

	for height := startBlockHeight; height >= 0; height-- {
		hash, err := exp.bc.GetHashByHeight(uint64(height))
		if err != nil {
			return []explorer.Execution{}, err
		}
		blkID := hex.EncodeToString(hash[:])

		blk, err := exp.bc.GetBlockByHeight(uint64(height))
		if err != nil {
			return []explorer.Execution{}, err
		}

		selps := make([]action.SealedEnvelope, 0)
		for _, selp := range blk.Actions {
			act := selp.Action()
			if _, ok := act.(*action.Execution); ok {
				selps = append(selps, selp)
			}
		}

		for i := len(selps) - 1; i >= 0; i-- {
			executionCount++

			if executionCount <= uint64(offset) {
				continue
			}

			if int64(len(res)) >= limit {
				return res, nil
			}

			explorerExecution, err := convertExecutionToExplorerExecution(selps[i], false)
			if err != nil {
				return []explorer.Execution{}, errors.Wrapf(err,
					"failed to convert execution %v to explorer's JSON execution", selps[i])
			}
			explorerExecution.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
			explorerExecution.BlockID = blkID
			res = append(res, explorerExecution)
		}
	}

	return res, nil
}

// GetExecutionByID returns execution by execution id
func (exp *Service) GetExecutionByID(executionID string) (explorer.Execution, error) {
	bytes, err := hex.DecodeString(executionID)
	if err != nil {
		return explorer.Execution{}, err
	}
	var executionHash hash.Hash32B
	copy(executionHash[:], bytes)

	return getExecution(exp.bc, exp.ap, executionHash, exp.idx, exp.cfg.UseRDS)
}

// GetExecutionsByAddress returns all executions associated with an address
func (exp *Service) GetExecutionsByAddress(address string, offset int64, limit int64) ([]explorer.Execution, error) {
	var res []explorer.Execution
	var executions []hash.Hash32B
	if exp.cfg.UseRDS {
		executionHistory, err := exp.idx.Indexer().GetExecutionHistory(address)
		if err != nil {
			return []explorer.Execution{}, err
		}
		executions = append(executions, executionHistory...)
	} else {
		executionsFromAddress, err := exp.bc.GetExecutionsFromAddress(address)
		if err != nil {
			return []explorer.Execution{}, err
		}

		executionsToAddress, err := exp.bc.GetExecutionsToAddress(address)
		if err != nil {
			return []explorer.Execution{}, err
		}

		executionsFromAddress = append(executionsFromAddress, executionsToAddress...)
		executions = append(executions, executionsFromAddress...)
	}

	for i, executionHash := range executions {
		if int64(i) < offset {
			continue
		}

		if int64(len(res)) >= limit {
			break
		}

		explorerExecution, err := getExecution(exp.bc, exp.ap, executionHash, exp.idx, exp.cfg.UseRDS)
		if err != nil {
			return []explorer.Execution{}, err
		}

		res = append(res, explorerExecution)
	}

	return res, nil
}

// GetUnconfirmedExecutionsByAddress returns all unconfirmed executions in actpool associated with an address
func (exp *Service) GetUnconfirmedExecutionsByAddress(address string, offset int64, limit int64) ([]explorer.Execution, error) {
	res := make([]explorer.Execution, 0)
	if _, err := exp.bc.StateByAddr(address); err != nil {
		return []explorer.Execution{}, err
	}

	selps := exp.ap.GetUnconfirmedActs(address)
	executionIndex := int64(0)
	for _, selp := range selps {
		if _, ok := selp.Action().(*action.Execution); !ok {
			continue
		}

		if executionIndex < offset {
			executionIndex++
			continue
		}

		if int64(len(res)) >= limit {
			break
		}

		explorerExecution, err := convertExecutionToExplorerExecution(selp, true)
		if err != nil {
			return []explorer.Execution{}, errors.Wrapf(err, "failed to convert execution %v to explorer's JSON execution", selp)
		}
		res = append(res, explorerExecution)
	}

	return res, nil
}

// GetExecutionsByBlockID returns executions in a block
func (exp *Service) GetExecutionsByBlockID(blkID string, offset int64, limit int64) ([]explorer.Execution, error) {
	var res []explorer.Execution
	bytes, err := hex.DecodeString(blkID)

	if err != nil {
		return []explorer.Execution{}, err
	}
	var hash hash.Hash32B
	copy(hash[:], bytes)

	blk, err := exp.bc.GetBlockByHash(hash)
	if err != nil {
		return []explorer.Execution{}, err
	}

	var num int
	for _, selp := range blk.Actions {
		if _, ok := selp.Action().(*action.Execution); !ok {
			continue
		}
		if int64(num) < offset {
			continue
		}

		if int64(len(res)) >= limit {
			break
		}

		explorerExecution, err := convertExecutionToExplorerExecution(selp, false)
		if err != nil {
			return []explorer.Execution{}, errors.Wrapf(err, "failed to convert execution %v to explorer's JSON execution", selp)
		}
		explorerExecution.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
		explorerExecution.BlockID = blkID
		res = append(res, explorerExecution)
		num++
	}
	return res, nil
}

// GetReceiptByExecutionID gets receipt with corresponding execution id
func (exp *Service) GetReceiptByExecutionID(id string) (explorer.Receipt, error) {
	bytes, err := hex.DecodeString(id)
	if err != nil {
		return explorer.Receipt{}, err
	}
	var executionHash hash.Hash32B
	copy(executionHash[:], bytes)
	receipt, err := exp.bc.GetReceiptByExecutionHash(executionHash)
	if err != nil {
		return explorer.Receipt{}, err
	}

	return convertReceiptToExplorerReceipt(receipt)
}

// GetReceiptByActionID gets receipt with corresponding action id
func (exp *Service) GetReceiptByActionID(id string) (explorer.Receipt, error) {
	bytes, err := hex.DecodeString(id)
	if err != nil {
		return explorer.Receipt{}, err
	}
	var actionHash hash.Hash32B
	copy(actionHash[:], bytes)
	receipt, err := exp.bc.GetReceiptByActionHash(actionHash)
	if err != nil {
		return explorer.Receipt{}, err
	}

	return convertReceiptToExplorerReceipt(receipt)
}

// GetCreateDeposit gets create deposit by ID
func (exp *Service) GetCreateDeposit(createDepositID string) (explorer.CreateDeposit, error) {
	bytes, err := hex.DecodeString(createDepositID)
	if err != nil {
		return explorer.CreateDeposit{}, err
	}
	var createDepositHash hash.Hash32B
	copy(createDepositHash[:], bytes)
	return getCreateDeposit(exp.bc, exp.ap, createDepositHash)
}

// GetCreateDepositsByAddress gets the relevant create deposits of an address
func (exp *Service) GetCreateDepositsByAddress(
	address string,
	offset int64,
	limit int64,
) ([]explorer.CreateDeposit, error) {
	res := make([]explorer.CreateDeposit, 0)

	depositsFromAddress, err := exp.bc.GetActionsFromAddress(address)
	if err != nil {
		return []explorer.CreateDeposit{}, err
	}

	for i, depositHash := range depositsFromAddress {
		if int64(i) < offset {
			continue
		}
		if int64(len(res)) >= limit {
			break
		}
		createDeposit, err := getCreateDeposit(exp.bc, exp.ap, depositHash)
		if err != nil {
			continue
		}

		res = append(res, createDeposit)
	}

	return res, nil
}

// GetSettleDeposit gets settle deposit by ID
func (exp *Service) GetSettleDeposit(settleDepositID string) (explorer.SettleDeposit, error) {
	bytes, err := hex.DecodeString(settleDepositID)
	if err != nil {
		return explorer.SettleDeposit{}, err
	}
	var settleDepositHash hash.Hash32B
	copy(settleDepositHash[:], bytes)
	return getSettleDeposit(exp.bc, exp.ap, settleDepositHash)
}

// GetSettleDepositsByAddress gets the relevant settle deposits of an address
func (exp *Service) GetSettleDepositsByAddress(
	address string,
	offset int64,
	limit int64,
) ([]explorer.SettleDeposit, error) {
	res := make([]explorer.SettleDeposit, 0)

	depositsToAddress, err := exp.bc.GetActionsToAddress(address)
	if err != nil {
		return []explorer.SettleDeposit{}, err
	}

	for i, depositHash := range depositsToAddress {
		if int64(i) < offset {
			continue
		}
		if int64(len(res)) >= limit {
			break
		}
		settleDeposit, err := getSettleDeposit(exp.bc, exp.ap, depositHash)
		if err != nil {
			continue
		}

		res = append(res, settleDeposit)
	}

	return res, nil
}

// GetLastBlocksByRange get block with height [offset-limit+1, offset]
func (exp *Service) GetLastBlocksByRange(offset int64, limit int64) ([]explorer.Block, error) {
	var res []explorer.Block

	for height := offset; height >= 0 && int64(len(res)) < limit; height-- {
		blk, err := exp.bc.GetBlockByHeight(uint64(height))
		if err != nil {
			return []explorer.Block{}, err
		}

		blockHeaderPb := blk.ConvertToBlockHeaderPb()
		hash, err := exp.bc.GetHashByHeight(uint64(height))
		if err != nil {
			return []explorer.Block{}, err
		}

		transfers, votes, executions := action.ClassifyActions(blk.Actions)
		totalAmount := big.NewInt(0)
		totalSize := uint32(0)
		for _, transfer := range transfers {
			totalAmount.Add(totalAmount, transfer.Amount())
			totalSize += transfer.TotalSize()
		}

		txRoot := blk.TxRoot()
		stateRoot := blk.StateRoot()
		explorerBlock := explorer.Block{
			ID:         hex.EncodeToString(hash[:]),
			Height:     int64(blockHeaderPb.Height),
			Timestamp:  blockHeaderPb.GetTimestamp().GetSeconds(),
			Transfers:  int64(len(transfers)),
			Votes:      int64(len(votes)),
			Executions: int64(len(executions)),
			Amount:     totalAmount.String(),
			Size:       int64(totalSize),
			GenerateBy: explorer.BlockGenerator{
				Name:    "",
				Address: keypair.EncodePublicKey(blk.PublicKey()),
			},
			TxRoot:    hex.EncodeToString(txRoot[:]),
			StateRoot: hex.EncodeToString(stateRoot[:]),
		}

		res = append(res, explorerBlock)
	}

	return res, nil
}

// GetBlockByID returns block by block id
func (exp *Service) GetBlockByID(blkID string) (explorer.Block, error) {
	bytes, err := hex.DecodeString(blkID)
	if err != nil {
		return explorer.Block{}, err
	}
	var hash hash.Hash32B
	copy(hash[:], bytes)

	blk, err := exp.bc.GetBlockByHash(hash)
	if err != nil {
		return explorer.Block{}, err
	}

	blkHeaderPb := blk.ConvertToBlockHeaderPb()

	transfers, votes, executions := action.ClassifyActions(blk.Actions)
	totalAmount := big.NewInt(0)
	totalSize := uint32(0)
	for _, transfer := range transfers {
		totalAmount.Add(totalAmount, transfer.Amount())
		totalSize += transfer.TotalSize()
	}

	txRoot := blk.TxRoot()
	stateRoot := blk.StateRoot()
	explorerBlock := explorer.Block{
		ID:         blkID,
		Height:     int64(blkHeaderPb.Height),
		Timestamp:  blkHeaderPb.GetTimestamp().GetSeconds(),
		Transfers:  int64(len(transfers)),
		Votes:      int64(len(votes)),
		Executions: int64(len(executions)),
		Amount:     totalAmount.String(),
		Size:       int64(totalSize),
		GenerateBy: explorer.BlockGenerator{
			Name:    "",
			Address: keypair.EncodePublicKey(blk.PublicKey()),
		},
		TxRoot:    hex.EncodeToString(txRoot[:]),
		StateRoot: hex.EncodeToString(stateRoot[:]),
	}

	return explorerBlock, nil
}

// GetCoinStatistic returns stats in blockchain
func (exp *Service) GetCoinStatistic() (explorer.CoinStatistic, error) {
	stat := explorer.CoinStatistic{}

	tipHeight := exp.bc.TipHeight()

	totalTransfers, err := exp.bc.GetTotalTransfers()
	if err != nil {
		return stat, err
	}

	totalVotes, err := exp.bc.GetTotalVotes()
	if err != nil {
		return stat, err
	}

	totalExecutions, err := exp.bc.GetTotalExecutions()
	if err != nil {
		return stat, err
	}

	blockLimit := int64(exp.cfg.TpsWindow)
	if blockLimit <= 0 {
		return stat, errors.Wrapf(ErrInternalServer, "block limit is %d", blockLimit)
	}

	// avoid genesis block
	if int64(tipHeight) < blockLimit {
		blockLimit = int64(tipHeight)
	}
	blks, err := exp.GetLastBlocksByRange(int64(tipHeight), blockLimit)
	if err != nil {
		return stat, err
	}

	if len(blks) == 0 {
		return stat, errors.New("get 0 blocks! not able to calculate aps")
	}

	timeDuration := blks[0].Timestamp - blks[len(blks)-1].Timestamp
	// if time duration is less than 1 second, we set it to be 1 second
	if timeDuration == 0 {
		timeDuration = 1
	}
	actionNumber := int64(0)
	for _, blk := range blks {
		actionNumber += blk.Transfers + blk.Votes + blk.Executions
	}
	aps := actionNumber / timeDuration

	explorerCoinStats := explorer.CoinStatistic{
		Height:     int64(tipHeight),
		Supply:     blockchain.Gen.TotalSupply.String(),
		Transfers:  int64(totalTransfers),
		Votes:      int64(totalVotes),
		Executions: int64(totalExecutions),
		Aps:        aps,
	}
	return explorerCoinStats, nil
}

// GetConsensusMetrics returns the latest consensus metrics
func (exp *Service) GetConsensusMetrics() (explorer.ConsensusMetrics, error) {
	cm, err := exp.c.Metrics()
	if err != nil {
		return explorer.ConsensusMetrics{}, err
	}
	dStrs := make([]string, len(cm.LatestDelegates))
	copy(dStrs, cm.LatestDelegates)
	var bpStr string
	if cm.LatestBlockProducer != "" {
		bpStr = cm.LatestBlockProducer
	}
	cStrs := make([]string, len(cm.Candidates))
	copy(cStrs, cm.Candidates)
	return explorer.ConsensusMetrics{
		LatestEpoch:         int64(cm.LatestEpoch),
		LatestDelegates:     dStrs,
		LatestBlockProducer: bpStr,
		Candidates:          cStrs,
	}, nil
}

// GetCandidateMetrics returns the latest delegates metrics
func (exp *Service) GetCandidateMetrics() (explorer.CandidateMetrics, error) {
	cm, err := exp.c.Metrics()
	if err != nil {
		return explorer.CandidateMetrics{}, errors.Wrapf(
			err,
			"Failed to get the candidate metrics")
	}
	delegateSet := make(map[string]bool, len(cm.LatestDelegates))
	for _, d := range cm.LatestDelegates {
		delegateSet[d] = true
	}
	allCandidates, err := exp.bc.CandidatesByHeight(cm.LatestHeight)
	if err != nil {
		return explorer.CandidateMetrics{}, errors.Wrapf(err,
			"Failed to get the candidate metrics")
	}
	candidates := make([]explorer.Candidate, len(cm.Candidates))
	for i, c := range allCandidates {
		candidates[i] = explorer.Candidate{
			Address:          c.Address,
			TotalVote:        c.Votes.String(),
			CreationHeight:   int64(c.CreationHeight),
			LastUpdateHeight: int64(c.LastUpdateHeight),
			IsDelegate:       false,
			IsProducer:       false,
		}
		if _, ok := delegateSet[c.Address]; ok {
			candidates[i].IsDelegate = true
		}
		if cm.LatestBlockProducer == c.Address {
			candidates[i].IsProducer = true
		}
	}

	return explorer.CandidateMetrics{
		Candidates:   candidates,
		LatestEpoch:  int64(cm.LatestEpoch),
		LatestHeight: int64(cm.LatestHeight),
	}, nil
}

// GetCandidateMetricsByHeight returns the candidates metrics for given height.
func (exp *Service) GetCandidateMetricsByHeight(h int64) (explorer.CandidateMetrics, error) {
	if h < 0 {
		return explorer.CandidateMetrics{}, errors.New("Invalid height")
	}
	allCandidates, err := exp.bc.CandidatesByHeight(uint64(h))
	if err != nil {
		return explorer.CandidateMetrics{}, errors.Wrapf(err,
			"Failed to get the candidate metrics")
	}
	candidates := make([]explorer.Candidate, 0, len(allCandidates))
	for _, c := range allCandidates {
		pubKey, err := keypair.BytesToPubKeyString(c.PublicKey[:])
		if err != nil {
			return explorer.CandidateMetrics{}, errors.Wrapf(err,
				"Invalid candidate pub key")
		}
		candidates = append(candidates, explorer.Candidate{
			Address:          c.Address,
			PubKey:           pubKey,
			TotalVote:        c.Votes.String(),
			CreationHeight:   int64(c.CreationHeight),
			LastUpdateHeight: int64(c.LastUpdateHeight),
		})
	}

	return explorer.CandidateMetrics{
		Candidates: candidates,
	}, nil
}

// SendTransfer sends a transfer
func (exp *Service) SendTransfer(tsfJSON explorer.SendTransferRequest) (resp explorer.SendTransferResponse, err error) {
	log.L().Debug("receive send transfer request")

	defer func() {
		succeed := "true"
		if err != nil {
			succeed = "false"
		}
		requestMtc.WithLabelValues("SendTransfer", succeed).Inc()
	}()

	actPb, err := convertExplorerTransferToActionPb(&tsfJSON, exp.cfg.MaxTransferPayloadBytes)
	if err != nil {
		return explorer.SendTransferResponse{}, err
	}
	// broadcast to the network
	if err = exp.broadcastHandler(exp.bc.ChainID(), actPb); err != nil {
		return explorer.SendTransferResponse{}, err
	}
	// send to actpool via dispatcher
	exp.dp.HandleBroadcast(exp.bc.ChainID(), actPb)

	tsf := &action.SealedEnvelope{}
	if err := tsf.LoadProto(actPb); err != nil {
		return explorer.SendTransferResponse{}, err
	}
	h := tsf.Hash()
	return explorer.SendTransferResponse{Hash: hex.EncodeToString(h[:])}, nil
}

// SendVote sends a vote
func (exp *Service) SendVote(voteJSON explorer.SendVoteRequest) (resp explorer.SendVoteResponse, err error) {
	log.L().Debug("receive send vote request")

	defer func() {
		succeed := "true"
		if err != nil {
			succeed = "false"
		}
		requestMtc.WithLabelValues("SendVote", succeed).Inc()
	}()

	selfPubKey, err := keypair.StringToPubKeyBytes(voteJSON.VoterPubKey)
	if err != nil {
		return explorer.SendVoteResponse{}, err
	}
	signature, err := hex.DecodeString(voteJSON.Signature)
	if err != nil {
		return explorer.SendVoteResponse{}, err
	}
	gasPrice, ok := big.NewInt(0).SetString(voteJSON.GasPrice, 10)
	if !ok {
		return explorer.SendVoteResponse{}, errors.New("failed to set vote gas price")
	}
	actPb := &iproto.ActionPb{
		Action: &iproto.ActionPb_Vote{
			Vote: &iproto.VotePb{
				VoteeAddress: voteJSON.Votee,
			},
		},
		Version:      uint32(voteJSON.Version),
		Sender:       voteJSON.Voter,
		SenderPubKey: selfPubKey,
		Nonce:        uint64(voteJSON.Nonce),
		GasLimit:     uint64(voteJSON.GasLimit),
		GasPrice:     gasPrice.Bytes(),
		Signature:    signature,
	}
	// broadcast to the network
	if err := exp.broadcastHandler(exp.bc.ChainID(), actPb); err != nil {
		return explorer.SendVoteResponse{}, err
	}
	// send to actpool via dispatcher
	exp.dp.HandleBroadcast(exp.bc.ChainID(), actPb)

	v := &action.SealedEnvelope{}
	if err := v.LoadProto(actPb); err != nil {
		return explorer.SendVoteResponse{}, err
	}
	h := v.Hash()
	return explorer.SendVoteResponse{Hash: hex.EncodeToString(h[:])}, nil
}

// PutSubChainBlock put block merkel root on root chain.
func (exp *Service) PutSubChainBlock(putBlockJSON explorer.PutSubChainBlockRequest) (resp explorer.PutSubChainBlockResponse, err error) {
	log.L().Debug("receive put block request")

	defer func() {
		succeed := "true"
		if err != nil {
			succeed = "false"
		}
		requestMtc.WithLabelValues("PutBlock", succeed).Inc()
	}()

	senderPubKey, err := keypair.StringToPubKeyBytes(putBlockJSON.SenderPubKey)
	if err != nil {
		return explorer.PutSubChainBlockResponse{}, err
	}
	signature, err := hex.DecodeString(putBlockJSON.Signature)
	if err != nil {
		return explorer.PutSubChainBlockResponse{}, err
	}
	gasPrice, ok := big.NewInt(0).SetString(putBlockJSON.GasPrice, 10)
	if !ok {
		return explorer.PutSubChainBlockResponse{}, errors.New("failed to set vote gas price")
	}

	roots := make([]*iproto.MerkleRoot, 0)
	for _, mr := range putBlockJSON.Roots {
		v, err := hex.DecodeString(mr.Value)
		if err != nil {
			return explorer.PutSubChainBlockResponse{}, err
		}
		roots = append(roots, &iproto.MerkleRoot{
			Name:  mr.Name,
			Value: v,
		})
	}
	actPb := &iproto.ActionPb{
		Action: &iproto.ActionPb_PutBlock{
			PutBlock: &iproto.PutBlockPb{
				SubChainAddress: putBlockJSON.SubChainAddress,
				Height:          uint64(putBlockJSON.Height),
				Roots:           roots,
			},
		},
		Version:      uint32(putBlockJSON.Version),
		Sender:       putBlockJSON.SenderAddress,
		SenderPubKey: senderPubKey,
		Nonce:        uint64(putBlockJSON.Nonce),
		GasLimit:     uint64(putBlockJSON.GasLimit),
		GasPrice:     gasPrice.Bytes(),
		Signature:    signature,
	}
	// broadcast to the network
	if err := exp.broadcastHandler(exp.bc.ChainID(), actPb); err != nil {
		return explorer.PutSubChainBlockResponse{}, err
	}
	// send to actpool via dispatcher
	exp.dp.HandleBroadcast(exp.bc.ChainID(), actPb)

	v := &action.SealedEnvelope{}
	if err := v.LoadProto(actPb); err != nil {
		return explorer.PutSubChainBlockResponse{}, err
	}
	h := v.Hash()
	return explorer.PutSubChainBlockResponse{Hash: hex.EncodeToString(h[:])}, nil
}

// SendAction is the API to send an action to blockchain.
func (exp *Service) SendAction(req explorer.SendActionRequest) (resp explorer.SendActionResponse, err error) {
	log.L().Debug("receive send action request")

	defer func() {
		succeed := "true"
		if err != nil {
			succeed = "false"
		}
		requestMtc.WithLabelValues("SendAction", succeed).Inc()
	}()
	var action iproto.ActionPb

	if err := jsonpb.UnmarshalString(req.Payload, &action); err != nil {
		return explorer.SendActionResponse{}, err
	}

	// broadcast to the network
	if err = exp.broadcastHandler(exp.bc.ChainID(), &action); err != nil {
		log.L().Warn("Failed to broadcast SendAction request.", zap.Error(err))
	}
	// send to actpool via dispatcher
	exp.dp.HandleBroadcast(exp.bc.ChainID(), &action)

	// TODO: include action hash
	return explorer.SendActionResponse{}, nil
}

// GetPeers return a list of node peers and itself's network addsress info.
func (exp *Service) GetPeers() (explorer.GetPeersResponse, error) {
	var peers []explorer.Node
	for _, p := range exp.neighborsHandler() {
		peers = append(peers, explorer.Node{
			Address: p.String(),
		})
	}
	return explorer.GetPeersResponse{
		Self:  explorer.Node{Address: exp.selfHandler().String()},
		Peers: peers,
	}, nil
}

// SendSmartContract sends a smart contract
func (exp *Service) SendSmartContract(execution explorer.Execution) (resp explorer.SendSmartContractResponse, err error) {
	log.L().Debug("receive send smart contract request")

	defer func() {
		succeed := "true"
		if err != nil {
			succeed = "false"
		}
		requestMtc.WithLabelValues("SendSmartContract", succeed).Inc()
	}()

	executorPubKey, err := keypair.StringToPubKeyBytes(execution.ExecutorPubKey)
	if err != nil {
		return explorer.SendSmartContractResponse{}, err
	}
	data, err := hex.DecodeString(execution.Data)
	if err != nil {
		return explorer.SendSmartContractResponse{}, err
	}
	signature, err := hex.DecodeString(execution.Signature)
	if err != nil {
		return explorer.SendSmartContractResponse{}, err
	}
	amount, ok := big.NewInt(0).SetString(execution.Amount, 10)
	if !ok {
		return explorer.SendSmartContractResponse{}, errors.New("failed to set execution amount")
	}
	gasPrice, ok := big.NewInt(0).SetString(execution.GasPrice, 10)
	if !ok {
		return explorer.SendSmartContractResponse{}, errors.New("failed to set execution gas price")
	}
	actPb := &iproto.ActionPb{
		Action: &iproto.ActionPb_Execution{
			Execution: &iproto.ExecutionPb{
				Amount:   amount.Bytes(),
				Contract: execution.Contract,
				Data:     data,
			},
		},
		Version:      uint32(execution.Version),
		Sender:       execution.Executor,
		SenderPubKey: executorPubKey,
		Nonce:        uint64(execution.Nonce),
		GasLimit:     uint64(execution.GasLimit),
		GasPrice:     gasPrice.Bytes(),
		Signature:    signature,
	}
	// broadcast to the network
	if err := exp.broadcastHandler(exp.bc.ChainID(), actPb); err != nil {
		return explorer.SendSmartContractResponse{}, err
	}
	// send to actpool via dispatcher
	exp.dp.HandleBroadcast(exp.bc.ChainID(), actPb)

	sc := &action.SealedEnvelope{}
	if err := sc.LoadProto(actPb); err != nil {
		return explorer.SendSmartContractResponse{}, err
	}
	h := sc.Hash()
	return explorer.SendSmartContractResponse{Hash: hex.EncodeToString(h[:])}, nil
}

// ReadExecutionState reads the state in a contract address specified by the slot
func (exp *Service) ReadExecutionState(execution explorer.Execution) (string, error) {
	log.L().Debug("receive read smart contract request")

	actPb, err := convertExplorerExecutionToActionPb(&execution)
	if err != nil {
		return "", err
	}
	selp := &action.SealedEnvelope{}
	if err := selp.LoadProto(actPb); err != nil {
		return "", err
	}
	sc, ok := selp.Action().(*action.Execution)
	if !ok {
		return "", errors.New("not execution")
	}

	res, err := exp.bc.ExecuteContractRead(sc)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(res.ReturnValue), nil
}

// GetBlockOrActionByHash get block or action by a hash
func (exp *Service) GetBlockOrActionByHash(hashStr string) (explorer.GetBlkOrActResponse, error) {
	if blk, err := exp.GetBlockByID(hashStr); err == nil {
		return explorer.GetBlkOrActResponse{Block: &blk}, nil
	}

	if tsf, err := exp.GetTransferByID(hashStr); err == nil {
		return explorer.GetBlkOrActResponse{Transfer: &tsf}, nil
	}

	if vote, err := exp.GetVoteByID(hashStr); err == nil {
		return explorer.GetBlkOrActResponse{Vote: &vote}, nil
	}

	if exe, err := exp.GetExecutionByID(hashStr); err == nil {
		return explorer.GetBlkOrActResponse{Execution: &exe}, nil
	}

	return explorer.GetBlkOrActResponse{}, nil
}

// CreateDeposit deposits balance from main-chain to sub-chain
func (exp *Service) CreateDeposit(req explorer.CreateDepositRequest) (res explorer.CreateDepositResponse, err error) {
	defer func() {
		succeed := "true"
		if err != nil {
			succeed = "false"
		}
		requestMtc.WithLabelValues("createDeposit", succeed).Inc()
	}()

	senderPubKey, err := keypair.StringToPubKeyBytes(req.SenderPubKey)
	if err != nil {
		return res, err
	}
	signature, err := hex.DecodeString(req.Signature)
	if err != nil {
		return res, err
	}
	amount, ok := big.NewInt(0).SetString(req.Amount, 10)
	if !ok {
		return res, errors.New("error when converting amount string into big int type")
	}
	gasPrice, ok := big.NewInt(0).SetString(req.GasPrice, 10)
	if !ok {
		return res, errors.New("error when converting gas price string into big int type")
	}
	actPb := &iproto.ActionPb{
		Action: &iproto.ActionPb_CreateDeposit{
			CreateDeposit: &iproto.CreateDepositPb{
				Amount:    amount.Bytes(),
				Recipient: req.Recipient,
			},
		},
		Version:      uint32(req.Version),
		Sender:       req.Sender,
		SenderPubKey: senderPubKey,
		Nonce:        uint64(req.Nonce),
		GasLimit:     uint64(req.GasLimit),
		GasPrice:     gasPrice.Bytes(),
		Signature:    signature,
	}

	// broadcast to the network
	if err := exp.broadcastHandler(exp.bc.ChainID(), actPb); err != nil {
		return res, err
	}
	// send to actpool via dispatcher
	exp.dp.HandleBroadcast(exp.bc.ChainID(), actPb)

	selp := &action.SealedEnvelope{}
	if err := selp.LoadProto(actPb); err != nil {
		return res, err
	}
	h := selp.Hash()
	return explorer.CreateDepositResponse{Hash: hex.EncodeToString(h[:])}, nil
}

// GetDeposits returns the deposits of a sub-chain in the given range in descending order by the index
func (exp *Service) GetDeposits(subChainID int64, offset int64, limit int64) ([]explorer.Deposit, error) {
	subChainsInOp, err := exp.mainChain.SubChainsInOperation()
	if err != nil {
		return nil, err
	}
	var targetSubChain mainchain.InOperation
	for _, subChainInOp := range subChainsInOp {
		if subChainInOp.ID == uint32(subChainID) {
			targetSubChain = subChainInOp
		}
	}
	if targetSubChain.ID != uint32(subChainID) {
		return nil, errors.Errorf("sub-chain %d is not found in operation", subChainID)
	}
	subChainAddr, err := address.BytesToAddress(targetSubChain.Addr)
	if err != nil {
		return nil, err
	}
	subChain, err := exp.mainChain.SubChain(subChainAddr)
	if err != nil {
		return nil, err
	}
	idx := uint64(offset)
	// If the last deposit index is lower than the start index, reset it
	if subChain.DepositCount-1 < idx {
		idx = subChain.DepositCount - 1
	}
	var deposits []explorer.Deposit
	for count := int64(0); count < limit; count++ {
		deposit, err := exp.mainChain.Deposit(subChainAddr, idx)
		if err != nil {
			return nil, err
		}
		recipient, err := address.BytesToAddress(deposit.Addr)
		if err != nil {
			return nil, err
		}
		deposits = append(deposits, explorer.Deposit{
			Amount:    deposit.Amount.String(),
			Address:   recipient.IotxAddress(),
			Confirmed: deposit.Confirmed,
		})
		if idx > 0 {
			idx--
		} else {
			break
		}
	}
	return deposits, nil
}

// SettleDeposit settles deposit on sub-chain
func (exp *Service) SettleDeposit(req explorer.SettleDepositRequest) (res explorer.SettleDepositResponse, err error) {
	defer func() {
		succeed := "true"
		if err != nil {
			succeed = "false"
		}
		requestMtc.WithLabelValues("settleDeposit", succeed).Inc()
	}()

	senderPubKey, err := keypair.StringToPubKeyBytes(req.SenderPubKey)
	if err != nil {
		return res, err
	}
	signature, err := hex.DecodeString(req.Signature)
	if err != nil {
		return res, err
	}
	amount, ok := big.NewInt(0).SetString(req.Amount, 10)
	if !ok {
		return res, errors.New("error when converting amount string into big int type")
	}
	gasPrice, ok := big.NewInt(0).SetString(req.GasPrice, 10)
	if !ok {
		return res, errors.New("error when converting gas price string into big int type")
	}
	actPb := &iproto.ActionPb{
		Action: &iproto.ActionPb_SettleDeposit{
			SettleDeposit: &iproto.SettleDepositPb{
				Amount:    amount.Bytes(),
				Index:     uint64(req.Index),
				Recipient: req.Recipient,
			},
		},
		Version:      uint32(req.Version),
		Sender:       req.Sender,
		SenderPubKey: senderPubKey,
		Nonce:        uint64(req.Nonce),
		GasLimit:     uint64(req.GasLimit),
		GasPrice:     gasPrice.Bytes(),
		Signature:    signature,
	}
	// broadcast to the network
	if err := exp.broadcastHandler(exp.bc.ChainID(), actPb); err != nil {
		return res, err
	}
	// send to actpool via dispatcher
	exp.dp.HandleBroadcast(exp.bc.ChainID(), actPb)

	deposit := &action.SealedEnvelope{}
	if err := deposit.LoadProto(actPb); err != nil {
		return res, err
	}
	h := deposit.Hash()
	return explorer.SettleDepositResponse{Hash: hex.EncodeToString(h[:])}, nil
}

// SuggestGasPrice suggest gas price
func (exp *Service) SuggestGasPrice() (int64, error) {
	return exp.gs.suggestGasPrice()
}

// EstimateGasForTransfer estimate gas for transfer
func (exp *Service) EstimateGasForTransfer(tsfJSON explorer.SendTransferRequest) (int64, error) {
	return exp.gs.estimateGasForTransfer(tsfJSON)
}

// EstimateGasForVote suggest gas for vote
func (exp *Service) EstimateGasForVote() (int64, error) {
	return exp.gs.estimateGasForVote()
}

// EstimateGasForSmartContract suggest gas for smart contract
func (exp *Service) EstimateGasForSmartContract(execution explorer.Execution) (int64, error) {
	return exp.gs.estimateGasForSmartContract(execution)
}

// GetStateRootHash gets the state root hash of a given block height
func (exp *Service) GetStateRootHash(blockHeight int64) (string, error) {
	rootHash, err := exp.bc.GetFactory().RootHashByHeight(uint64(blockHeight))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(rootHash[:]), nil
}

// getTransfer takes in a blockchain and transferHash and returns an Explorer Transfer
func getTransfer(bc blockchain.Blockchain, ap actpool.ActPool, transferHash hash.Hash32B, idx *indexservice.Server, useRDS bool) (explorer.Transfer, error) {
	explorerTransfer := explorer.Transfer{}

	selp, err := bc.GetActionByActionHash(transferHash)
	if err != nil {
		// Try to fetch pending transfer from actpool
		selp, err := ap.GetActionByHash(transferHash)
		if err != nil {
			return explorerTransfer, err
		}
		return convertTsfToExplorerTsf(selp, true)
	}

	// Fetch from block
	var blkHash hash.Hash32B
	if useRDS {
		hash, err := idx.Indexer().GetBlockByTransfer(transferHash)
		if err != nil {
			return explorerTransfer, err
		}
		blkHash = hash
	} else {
		hash, err := bc.GetBlockHashByTransferHash(transferHash)
		if err != nil {
			return explorerTransfer, err
		}
		blkHash = hash
	}

	blk, err := bc.GetBlockByHash(blkHash)
	if err != nil {
		return explorerTransfer, err
	}

	if explorerTransfer, err = convertTsfToExplorerTsf(selp, false); err != nil {
		return explorerTransfer, errors.Wrapf(err, "failed to convert transfer %v to explorer's JSON transfer", selp)
	}
	explorerTransfer.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
	explorerTransfer.BlockID = hex.EncodeToString(blkHash[:])
	return explorerTransfer, nil
}

// getVote takes in a blockchain and voteHash and returns an Explorer Vote
func getVote(bc blockchain.Blockchain, ap actpool.ActPool, voteHash hash.Hash32B, idx *indexservice.Server, useRDS bool) (explorer.Vote, error) {
	explorerVote := explorer.Vote{}

	selp, err := bc.GetActionByActionHash(voteHash)
	if err != nil {
		// Try to fetch pending vote from actpool
		selp, err := ap.GetActionByHash(voteHash)
		if err != nil {
			return explorerVote, err
		}
		return convertVoteToExplorerVote(selp, true)
	}

	// Fetch from block
	var blkHash hash.Hash32B
	if useRDS {
		hash, err := idx.Indexer().GetBlockByVote(voteHash)
		if err != nil {
			return explorerVote, err
		}
		blkHash = hash
	} else {
		hash, err := bc.GetBlockHashByVoteHash(voteHash)
		if err != nil {
			return explorerVote, err
		}
		blkHash = hash
	}

	blk, err := bc.GetBlockByHash(blkHash)
	if err != nil {
		return explorerVote, err
	}

	if explorerVote, err = convertVoteToExplorerVote(selp, false); err != nil {
		return explorerVote, errors.Wrapf(err, "failed to convert vote %v to explorer's JSON vote", selp)
	}
	explorerVote.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
	explorerVote.BlockID = hex.EncodeToString(blkHash[:])
	return explorerVote, nil
}

// getExecution takes in a blockchain and executionHash and returns an Explorer execution
func getExecution(bc blockchain.Blockchain, ap actpool.ActPool, executionHash hash.Hash32B, idx *indexservice.Server, useRDS bool) (explorer.Execution, error) {
	explorerExecution := explorer.Execution{}

	selp, err := bc.GetActionByActionHash(executionHash)
	if err != nil {
		// Try to fetch pending execution from actpool
		selp, err = ap.GetActionByHash(executionHash)
		if err != nil {
			return explorerExecution, err
		}
		return convertExecutionToExplorerExecution(selp, true)
	}

	// Fetch from block
	var blkHash hash.Hash32B
	if useRDS {
		hash, err := idx.Indexer().GetBlockByExecution(executionHash)
		if err != nil {
			return explorerExecution, err
		}
		blkHash = hash
	} else {
		hash, err := bc.GetBlockHashByExecutionHash(executionHash)
		if err != nil {
			return explorerExecution, err
		}
		blkHash = hash
	}

	blk, err := bc.GetBlockByHash(blkHash)
	if err != nil {
		return explorerExecution, err
	}

	if explorerExecution, err = convertExecutionToExplorerExecution(selp, false); err != nil {
		return explorerExecution, errors.Wrapf(err, "failed to convert execution %v to explorer's JSON execution", selp)
	}
	explorerExecution.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
	explorerExecution.BlockID = hex.EncodeToString(blkHash[:])
	return explorerExecution, nil
}

// getCreateDeposit takes in a blockchain and create deposit hash and returns an Explorer create deposit
func getCreateDeposit(
	bc blockchain.Blockchain,
	ap actpool.ActPool,
	createDepositHash hash.Hash32B,
) (explorer.CreateDeposit, error) {
	pending := false
	var selp action.SealedEnvelope
	var err error
	selp, err = bc.GetActionByActionHash(createDepositHash)
	if err != nil {
		// Try to fetch pending create deposit from actpool
		selp, err = ap.GetActionByHash(createDepositHash)
		if err != nil {
			return explorer.CreateDeposit{}, err
		}
		pending = true
	}

	// Fetch from block
	blkHash, err := bc.GetBlockHashByActionHash(createDepositHash)
	if err != nil {
		return explorer.CreateDeposit{}, err
	}
	blk, err := bc.GetBlockByHash(blkHash)
	if err != nil {
		return explorer.CreateDeposit{}, err
	}

	cd, err := castActionToCreateDeposit(selp, pending)
	if err != nil {
		return explorer.CreateDeposit{}, err
	}
	cd.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
	cd.BlockID = hex.EncodeToString(blkHash[:])
	return cd, nil
}

func castActionToCreateDeposit(selp action.SealedEnvelope, pending bool) (explorer.CreateDeposit, error) {
	cd, ok := selp.Action().(*action.CreateDeposit)
	if !ok {
		return explorer.CreateDeposit{}, errors.Wrap(ErrAction, "action type is not create deposit")
	}
	hash := selp.Hash()
	createDeposit := explorer.CreateDeposit{
		Nonce:     int64(selp.Nonce()),
		ID:        hex.EncodeToString(hash[:]),
		Sender:    cd.Sender(),
		Recipient: cd.Recipient(),
		Fee:       "", // TODO: we need to get the actual fee.
		GasLimit:  int64(selp.GasLimit()),
		IsPending: pending,
	}
	if cd.Amount() != nil && len(cd.Amount().String()) > 0 {
		createDeposit.Amount = cd.Amount().String()
	}
	if selp.GasPrice() != nil && len(selp.GasPrice().String()) > 0 {
		createDeposit.GasPrice = selp.GasPrice().String()
	}
	return createDeposit, nil
}

// getSettleDeposit takes in a blockchain and settle deposit hash and returns an Explorer settle deposit
func getSettleDeposit(
	bc blockchain.Blockchain,
	ap actpool.ActPool,
	settleDepositHash hash.Hash32B,
) (explorer.SettleDeposit, error) {
	pending := false
	var selp action.SealedEnvelope
	var err error
	selp, err = bc.GetActionByActionHash(settleDepositHash)
	if err != nil {
		// Try to fetch pending settle deposit from actpool
		selp, err = ap.GetActionByHash(settleDepositHash)
		if err != nil {
			return explorer.SettleDeposit{}, err
		}
		pending = true
	}

	// Fetch from block
	blkHash, err := bc.GetBlockHashByActionHash(settleDepositHash)
	if err != nil {
		return explorer.SettleDeposit{}, err
	}
	blk, err := bc.GetBlockByHash(blkHash)
	if err != nil {
		return explorer.SettleDeposit{}, err
	}

	sd, err := castActionToSettleDeposit(selp, pending)
	if err != nil {
		return explorer.SettleDeposit{}, err
	}
	sd.Timestamp = blk.ConvertToBlockHeaderPb().GetTimestamp().GetSeconds()
	sd.BlockID = hex.EncodeToString(blkHash[:])
	return sd, nil
}

func castActionToSettleDeposit(selp action.SealedEnvelope, pending bool) (explorer.SettleDeposit, error) {
	sd, ok := selp.Action().(*action.SettleDeposit)
	if !ok {
		return explorer.SettleDeposit{}, errors.Wrap(ErrAction, "action type is not settle deposit")
	}
	hash := selp.Hash()
	settleDeposit := explorer.SettleDeposit{
		Nonce:     int64(selp.Nonce()),
		ID:        hex.EncodeToString(hash[:]),
		Sender:    sd.Sender(),
		Recipient: sd.Recipient(),
		Index:     int64(sd.Index()),
		Fee:       "", // TODO: we need to get the actual fee.
		GasLimit:  int64(selp.GasLimit()),
		IsPending: pending,
	}
	if sd.Amount() != nil && len(sd.Amount().String()) > 0 {
		settleDeposit.Amount = sd.Amount().String()
	}
	if selp.GasPrice() != nil && len(selp.GasPrice().String()) > 0 {
		settleDeposit.GasPrice = selp.GasPrice().String()
	}
	return settleDeposit, nil
}

func convertTsfToExplorerTsf(selp action.SealedEnvelope, isPending bool) (explorer.Transfer, error) {
	transfer, ok := selp.Action().(*action.Transfer)
	if !ok {
		return explorer.Transfer{}, errors.Wrap(ErrTransfer, "action is not transfer")
	}

	if transfer == nil {
		return explorer.Transfer{}, errors.Wrap(ErrTransfer, "transfer cannot be nil")
	}
	hash := selp.Hash()
	explorerTransfer := explorer.Transfer{
		Nonce:      int64(selp.Nonce()),
		ID:         hex.EncodeToString(hash[:]),
		Sender:     transfer.Sender(),
		Recipient:  transfer.Recipient(),
		Fee:        "", // TODO: we need to get the actual fee.
		Payload:    hex.EncodeToString(transfer.Payload()),
		GasLimit:   int64(selp.GasLimit()),
		IsCoinbase: transfer.IsCoinbase(),
		IsPending:  isPending,
	}
	if transfer.Amount() != nil && len(transfer.Amount().String()) > 0 {
		explorerTransfer.Amount = transfer.Amount().String()
	}
	if selp.GasPrice() != nil && len(selp.GasPrice().String()) > 0 {
		explorerTransfer.GasPrice = selp.GasPrice().String()
	}
	return explorerTransfer, nil
}

func convertVoteToExplorerVote(selp action.SealedEnvelope, isPending bool) (explorer.Vote, error) {
	vote, ok := selp.Action().(*action.Vote)
	if !ok {
		return explorer.Vote{}, errors.Wrap(ErrTransfer, "action is not vote")
	}
	if vote == nil {
		return explorer.Vote{}, errors.Wrap(ErrVote, "vote cannot be nil")
	}
	hash := selp.Hash()
	voterPubkey := vote.VoterPublicKey()
	explorerVote := explorer.Vote{
		ID:          hex.EncodeToString(hash[:]),
		Nonce:       int64(selp.Nonce()),
		Voter:       vote.Voter(),
		VoterPubKey: hex.EncodeToString(voterPubkey[:]),
		Votee:       vote.Votee(),
		GasLimit:    int64(selp.GasLimit()),
		GasPrice:    selp.GasPrice().String(),
		IsPending:   isPending,
	}
	return explorerVote, nil
}

func convertExecutionToExplorerExecution(selp action.SealedEnvelope, isPending bool) (explorer.Execution, error) {
	execution, ok := selp.Action().(*action.Execution)
	if !ok {
		return explorer.Execution{}, errors.Wrap(ErrTransfer, "action is not execution")
	}
	if execution == nil {
		return explorer.Execution{}, errors.Wrap(ErrExecution, "execution cannot be nil")
	}
	hash := execution.Hash()
	explorerExecution := explorer.Execution{
		Nonce:     int64(selp.Nonce()),
		ID:        hex.EncodeToString(hash[:]),
		Executor:  execution.Executor(),
		Contract:  execution.Contract(),
		GasLimit:  int64(selp.GasLimit()),
		Data:      hex.EncodeToString(execution.Data()),
		IsPending: isPending,
	}
	if execution.Amount() != nil && len(execution.Amount().String()) > 0 {
		explorerExecution.Amount = execution.Amount().String()
	}
	if selp.GasPrice() != nil && len(selp.GasPrice().String()) > 0 {
		explorerExecution.GasPrice = selp.GasPrice().String()
	}
	return explorerExecution, nil
}

func convertReceiptToExplorerReceipt(receipt *action.Receipt) (explorer.Receipt, error) {
	if receipt == nil {
		return explorer.Receipt{}, errors.Wrap(ErrReceipt, "receipt cannot be nil")
	}
	logs := []explorer.Log{}
	for _, log := range receipt.Logs {
		topics := []string{}
		for _, topic := range log.Topics {
			topics = append(topics, hex.EncodeToString(topic[:]))
		}
		logs = append(logs, explorer.Log{
			Address:     log.Address,
			Topics:      topics,
			Data:        hex.EncodeToString(log.Data),
			BlockNumber: int64(log.BlockNumber),
			TxnHash:     hex.EncodeToString(log.TxnHash[:]),
			BlockHash:   hex.EncodeToString(log.BlockHash[:]),
			Index:       int64(log.Index),
		})
	}

	return explorer.Receipt{
		ReturnValue:     hex.EncodeToString(receipt.ReturnValue),
		Status:          int64(receipt.Status),
		Hash:            hex.EncodeToString(receipt.Hash[:]),
		GasConsumed:     int64(receipt.GasConsumed),
		ContractAddress: receipt.ContractAddress,
		Logs:            logs,
	}, nil
}

func convertExplorerExecutionToActionPb(execution *explorer.Execution) (*iproto.ActionPb, error) {
	executorPubKey, err := keypair.StringToPubKeyBytes(execution.ExecutorPubKey)
	if err != nil {
		return nil, err
	}
	data, err := hex.DecodeString(execution.Data)
	if err != nil {
		return nil, err
	}
	signature, err := hex.DecodeString(execution.Signature)
	if err != nil {
		return nil, err
	}
	amount, ok := big.NewInt(0).SetString(execution.Amount, 10)
	if !ok {
		return nil, errors.New("failed to set execution amount")
	}
	gasPrice, ok := big.NewInt(0).SetString(execution.GasPrice, 10)
	if !ok {
		return nil, errors.New("failed to set execution gas price")
	}
	actPb := &iproto.ActionPb{
		Action: &iproto.ActionPb_Execution{
			Execution: &iproto.ExecutionPb{
				Amount:   amount.Bytes(),
				Contract: execution.Contract,
				Data:     data,
			},
		},
		Version:      uint32(execution.Version),
		Sender:       execution.Executor,
		SenderPubKey: executorPubKey,
		Nonce:        uint64(execution.Nonce),
		GasLimit:     uint64(execution.GasLimit),
		GasPrice:     gasPrice.Bytes(),
		Signature:    signature,
	}
	return actPb, nil
}

func convertExplorerTransferToActionPb(tsfJSON *explorer.SendTransferRequest,
	MaxTransferPayloadBytes uint64) (*iproto.ActionPb, error) {
	payload, err := hex.DecodeString(tsfJSON.Payload)
	if err != nil {
		return nil, err
	}
	if uint64(len(payload)) > MaxTransferPayloadBytes {
		return nil, errors.Wrapf(
			ErrTransfer,
			"transfer payload contains %d bytes, and is longer than %d bytes limit",
			len(payload),
			MaxTransferPayloadBytes,
		)
	}
	senderPubKey, err := keypair.StringToPubKeyBytes(tsfJSON.SenderPubKey)
	if err != nil {
		return nil, err
	}
	signature, err := hex.DecodeString(tsfJSON.Signature)
	if err != nil {
		return nil, err
	}
	amount, ok := big.NewInt(0).SetString(tsfJSON.Amount, 10)
	if !ok {
		return nil, errors.New("failed to set transfer amount")
	}
	gasPrice, ok := big.NewInt(0).SetString(tsfJSON.GasPrice, 10)
	if !ok {
		return nil, errors.New("failed to set transfer gas price")
	}
	actPb := &iproto.ActionPb{
		Action: &iproto.ActionPb_Transfer{
			Transfer: &iproto.TransferPb{
				Amount:     amount.Bytes(),
				Recipient:  tsfJSON.Recipient,
				Payload:    payload,
				IsCoinbase: tsfJSON.IsCoinbase,
			},
		},
		Version:      uint32(tsfJSON.Version),
		Sender:       tsfJSON.Sender,
		SenderPubKey: senderPubKey,
		Nonce:        uint64(tsfJSON.Nonce),
		GasLimit:     uint64(tsfJSON.GasLimit),
		GasPrice:     gasPrice.Bytes(),
		Signature:    signature,
	}
	return actPb, nil
}
