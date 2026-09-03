package main

import (
	"testing"
)

func TestGoldenVector(t *testing.T) {
	username := "202401001"
	password := "TestPassword123"
	ip := "10.61.34.79"
	acId := 1
	token := "3c20ef0d07611994b7effdab1a0a4e45523ad94d68f22bc008f7b1762aa99048"

	expectedInfo := "{SRBX1}Ql6APrLvdePYvDZz7WPxEn6BSt6qlzp0VBaeqv1trAnMOiUzWNBQ5AweH+lJ1L5DGXFuEyvQqUv9M2UkoQSSd4uAINvY6Cv//6l+esZXP9f9JAfvhQ1aFq/2cU6YkRNt06p8LegNKScp7W2O"
	expectedHmd5 := "52163b2e4ccac5a00a57c54f3d77fa83"
	expectedChksum := "47661ff70e5dbdf22dcc1144023a9c5ae78c528d"

	calcHmd5 := hmd5(password, token)
	if calcHmd5 != expectedHmd5 {
		t.Fatalf("hmd5 mismatch: got %s, want %s", calcHmd5, expectedHmd5)
	}

	calcInfo := buildInfo(username, password, ip, acId, token)
	if calcInfo != expectedInfo {
		t.Fatalf("info mismatch: got %s, want %s", calcInfo, expectedInfo)
	}

	calcChksum := buildChksum(token, username, calcHmd5, acId, ip, 200, 1, calcInfo)
	if calcChksum != expectedChksum {
		t.Fatalf("chksum mismatch: got %s, want %s", calcChksum, expectedChksum)
	}
}
