package main

import "testing"

func TestPrivateListen(t *testing.T) {
	for _, a := range []string{"127.0.0.1:1", "10.0.0.1:2", "192.168.1.1:3", "[::1]:4"} {
		if !privateListen(a) {
			t.Errorf("should be private: %s", a)
		}
	}
	for _, a := range []string{"0.0.0.0:1", "8.8.8.8:2", ":8080", "bad"} {
		if privateListen(a) {
			t.Errorf("should be rejected: %s", a)
		}
	}
}
