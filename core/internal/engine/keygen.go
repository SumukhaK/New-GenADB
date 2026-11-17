package engine

// Keygen loads (or creates) the identity key in state and returns its public
// key in the form token issuers bind to ("cnf.key").
func Keygen(state string) (string, error) {
	k, err := loadOrCreateKey(state)
	if err != nil {
		return "", err
	}
	return pubString(k), nil
}
