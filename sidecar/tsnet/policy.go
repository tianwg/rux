package main

// admitPeer is the built-in Tailscale column of the remote-access page.
// A tagged peer has no person to match, so it is admitted only when members
// are allowed. Otherwise only the user who owns this device is admitted.
func admitPeer(ownerUser, peerUser string, peerTagged, allowMembers bool) bool {
	if peerTagged {
		return allowMembers
	}
	if allowMembers {
		return peerUser != ""
	}
	return ownerUser != "" && ownerUser == peerUser
}
