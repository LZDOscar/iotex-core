// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package account

import (
	"context"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iotexproject/iotex-core/action/protocol"
	"github.com/iotexproject/iotex-core/config"
	"github.com/iotexproject/iotex-core/db"
	"github.com/iotexproject/iotex-core/iotxaddress"
	"github.com/iotexproject/iotex-core/state"
	"github.com/iotexproject/iotex-core/state/factory"
	"github.com/iotexproject/iotex-core/test/testaddress"
	"github.com/iotexproject/iotex-core/testutil"
)

func TestLoadOrCreateAccountState(t *testing.T) {
	require := require.New(t)

	cfg := config.Default
	sf, err := factory.NewFactory(cfg, factory.PrecreatedTrieDBOption(db.NewMemKVStore()))
	require.NoError(err)
	require.NoError(sf.Start(context.Background()))
	addr, err := iotxaddress.NewAddress(true, []byte{0xa4, 0x00, 0x00, 0x00})
	require.Nil(err)
	ws, err := sf.NewWorkingSet()
	require.NoError(err)
	addrHash, err := iotxaddress.AddressToPKHash(addr.RawAddress)
	require.NoError(err)
	s, err := LoadAccount(ws, addrHash)
	require.NoError(err)
	require.Equal(s, state.EmptyAccount)
	s, err = LoadOrCreateAccount(ws, addr.RawAddress, big.NewInt(5))
	require.NoError(err)
	s, err = LoadAccount(ws, addrHash)
	require.NoError(err)
	require.Equal(uint64(0x0), s.Nonce)
	require.Equal("5", s.Balance.String())

	gasLimit := testutil.TestGasLimit
	ctx := protocol.WithRunActionsCtx(context.Background(),
		protocol.RunActionsCtx{
			ProducerAddr:    testaddress.IotxAddrinfo["producer"].RawAddress,
			GasLimit:        &gasLimit,
			EnableGasCharge: testutil.EnableGasCharge,
		})
	_, _, err = ws.RunActions(ctx, 0, nil)
	require.NoError(err)
	require.NoError(sf.Commit(ws))
	ss, err := sf.AccountState(addr.RawAddress)
	require.Nil(err)
	require.Equal(uint64(0x0), ss.Nonce)
	require.Equal("5", ss.Balance.String())
}
