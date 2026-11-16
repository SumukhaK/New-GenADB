package main

import "flag"

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	state := fs.String("state", ".", "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	k, err := loadOrCreateKey(*state)
	if err != nil {
		return err
	}
	emit("pubkey", map[string]any{"pubkey": pubString(k)})
	return nil
}
