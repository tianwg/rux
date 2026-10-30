package main

import "testing"

func TestAdmitPeer(t *testing.T) {
	if !admitPeer("user-1", "user-1", false, false) {
		t.Fatal("owner")
	}
	if admitPeer("user-1", "user-2", false, false) {
		t.Fatal("other user")
	}
	if !admitPeer("user-1", "user-2", false, true) {
		t.Fatal("member")
	}
	if admitPeer("", "user-2", true, false) {
		t.Fatal("tagged device without members")
	}
	if !admitPeer("", "", true, true) {
		t.Fatal("tagged peer when members are allowed")
	}
	if admitPeer("", "", false, false) {
		t.Fatal("anonymous")
	}
}
