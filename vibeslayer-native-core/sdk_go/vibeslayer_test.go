package vibeslayer

import (
	"encoding/hex"
	"os"
	"testing"
)

func TestInteropWithRustVspk2(t *testing.T) {
	vspkPath := os.Getenv("VS_INTEROP_FILE")
	keyHex := os.Getenv("VS_INTEROP_KEY")
	if vspkPath == "" || keyHex == "" {
		t.Skip("VS_INTEROP_FILE not set")
	}
	rawKey, err := hex.DecodeString(keyHex)
	if err != nil || len(rawKey) != 32 {
		t.Fatalf("bad key: %v", err)
	}
	var mk [32]byte
	copy(mk[:], rawKey)

	blob, err := os.ReadFile(vspkPath)
	if err != nil {
		t.Fatalf("read vspk: %v", err)
	}

	p := &Policy{
		Enabled:   true,
		MasterKey: mk,
		Actions: map[string]ActionRule{
			"cfg.read": {
				Domain:  "backend",
				Context: "prod-cluster",
				AssetID: "shared-cfg-v1",
				Params: map[string]ParamRule{
					"seats": {Kind: ParamInt, Min: 1, Max: 100},
				},
			},
		},
	}

	if _, err := p.UnsealActionVspk2("cfg.read", map[string]any{"seats": int64(999)}, blob); err == nil {
		t.Fatal("expected out-of-range seats to fail")
	}

	plain, err := p.UnsealActionVspk2("cfg.read", map[string]any{"seats": int64(10)}, blob)
	if err != nil {
		t.Fatalf("UnsealActionVspk2 failed: %v", err)
	}
	if string(plain) != "POLYGLOT_PAYLOAD_RUST_TO_C_GO_PYTHON_2026_OK" {
		t.Fatalf("unexpected plaintext: %q", string(plain))
	}
}

func TestInteropWithRustVspk3(t *testing.T) {
	vspk3Path := os.Getenv("VS_INTEROP_V3_FILE")
	keyHex := os.Getenv("VS_INTEROP_V3_KEY")
	if vspk3Path == "" || keyHex == "" {
		t.Skip("VS_INTEROP_V3_FILE not set")
	}
	rawKey, err := hex.DecodeString(keyHex)
	if err != nil || len(rawKey) != 32 {
		t.Fatalf("bad key: %v", err)
	}
	var mk [32]byte
	copy(mk[:], rawKey)

	blob, err := os.ReadFile(vspk3Path)
	if err != nil {
		t.Fatalf("read vspk3: %v", err)
	}

	p := &Policy{
		Enabled:   true,
		MasterKey: mk,
		Actions: map[string]ActionRule{
			"cfg.read.v3": {
				Domain:  "backend",
				Context: "prod-cluster",
				AssetID: "svc-secrets-v3",
				Params: map[string]ParamRule{
					"tier":    {Kind: ParamStr},
					"enabled": {Kind: ParamBool},
				},
			},
		},
	}

	validArgs := map[string]any{"tier": "enterprise", "enabled": true}
	plain, err := p.UnsealActionVspk3("cfg.read.v3", validArgs, "svc-secrets-v3", blob)
	if err != nil {
		t.Fatalf("UnsealActionVspk3 failed: %v", err)
	}
	if string(plain) != "POLYGLOT_VSPK3_RUST_TO_C_GO_PYTHON_2026_OK" {
		t.Fatalf("unexpected vspk3 plaintext: %q", string(plain))
	}

	// Wrong assetId fails closed
	if _, err := p.UnsealActionVspk3("cfg.read.v3", validArgs, "wrong-asset", blob); err == nil {
		t.Fatal("expected wrong assetId to fail")
	}

	// 1-byte tamper in ciphertext fails closed
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0x55
	if _, err := p.UnsealActionVspk3("cfg.read.v3", validArgs, "svc-secrets-v3", tampered); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}

	// Wrong master key fails CMT-4 check before AEAD
	pWrong := *p
	pWrong.MasterKey[0] ^= 0x01
	if _, err := pWrong.UnsealActionVspk3("cfg.read.v3", validArgs, "svc-secrets-v3", blob); err == nil {
		t.Fatal("expected wrong key CMT-4 to fail")
	}
}
