// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// selfCmd represents the self command
var selfCmd = &cobra.Command{
	Use:   "self",
	Short: "Returns this node's address",
	Long:  `Returns this node's address`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(self())
	},
}

func self() string {
	// TODO: address should be return from the node API instead of a local config
	return ""
	/*
		cfg, err := getCfg()
		if err != nil {
			return ""
		}
		pubk, err := keypair.DecodePublicKey(cfg.Chain.ProducerPubKey)
		if err != nil {
			return ""
		}
		addr, err := iotxaddress.GetAddress(pubk, iotxaddress.IsTestnet, iotxaddress.ChainID)
		if err != nil {
			return ""
		}

		rawAddr := addr.RawAddress
		return fmt.Sprintf("this node's address is %s", rawAddr)
	*/
}

func init() {
	rootCmd.AddCommand(selfCmd)
}
