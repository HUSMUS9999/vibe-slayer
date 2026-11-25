package vibeslayer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

func TestVspk3V2StreamRoundtripAndUnifiedAuthErrors(t *testing.T) {
	var mk [32]byte
	for i := range mk {
		mk[i] = byte(i*7 + 3)
	}

	sizes := []int{0, 1, 1020, 1024, 65535, 65536, 65537, 200000}
	for _, sz := range sizes {
		plain := make([]byte, sz)
		for i := range plain {
			plain[i] = byte((i*31 + 17) & 0xff)
		}
		sealed, err := SealVspk3V2(mk, "weights", "model-v2", "prod", plain)
		if err != nil {
			t.Fatalf("size %d seal failed: %v", sz, err)
		}
		opened, err := UnsealVspk3V2(mk, "weights", "model-v2", "prod", sealed)
		if err != nil {
			t.Fatalf("size %d unseal failed: %v", sz, err)
		}
		if !bytes.Equal(opened, plain) {
			t.Fatalf("size %d plaintext mismatch", sz)
		}

		// Tamper ciphertext byte -> unified ErrVaultAuthFailed
		tampered := append([]byte(nil), sealed...)
		tampered[len(tampered)-1] ^= 0x42
		if _, err := UnsealVspk3V2(mk, "weights", "model-v2", "prod", tampered); !errors.Is(err, ErrVaultAuthFailed) {
			t.Fatalf("size %d tampered expected ErrVaultAuthFailed, got %v", sz, err)
		}

		// Wrong key -> identical unified ErrVaultAuthFailed (no error oracle!)
		wrongKey := mk
		wrongKey[0] ^= 0x01
		if _, err := UnsealVspk3V2(wrongKey, "weights", "model-v2", "prod", sealed); !errors.Is(err, ErrVaultAuthFailed) {
			t.Fatalf("size %d wrong key expected ErrVaultAuthFailed, got %v", sz, err)
		}

		// Wrong context -> identical unified ErrVaultAuthFailed
		if _, err := UnsealVspk3V2(mk, "weights", "model-v2", "staging", sealed); !errors.Is(err, ErrVaultAuthFailed) {
			t.Fatalf("size %d wrong context expected ErrVaultAuthFailed, got %v", sz, err)
		}
	}

	// Chunk reordering rejection on multi-chunk container
	plain := bytes.Repeat([]byte("A"), 150000)
	sealed, err := SealVspk3V2(mk, "weights", "reorder", "prod", plain)
	if err != nil {
		t.Fatal(err)
	}
	reordered := append([]byte(nil), sealed...)
	c0Start := Vspk3V2PrefixLen
	c1Start := Vspk3V2PrefixLen + Vspk3V2IntermediateRecordLen
	tmp := append([]byte(nil), reordered[c0Start:c1Start]...)
	copy(reordered[c0Start:c1Start], reordered[c1Start:c1Start+Vspk3V2IntermediateRecordLen])
	copy(reordered[c1Start:c1Start+Vspk3V2IntermediateRecordLen], tmp)
	if _, err := UnsealVspk3V2(mk, "weights", "reorder", "prod", reordered); !errors.Is(err, ErrVaultAuthFailed) {
		t.Fatalf("expected reordered chunks to fail with ErrVaultAuthFailed, got %v", err)
	}
}

func TestInteropWithRustVspk3V2(t *testing.T) {
	v2Path := os.Getenv("VS_INTEROP_V3V2_FILE")
	keyHex := os.Getenv("VS_INTEROP_V3V2_KEY")
	if v2Path == "" || keyHex == "" {
		t.Skip("VS_INTEROP_V3V2_FILE not set")
	}
	rawKey, err := hex.DecodeString(keyHex)
	if err != nil || len(rawKey) != 32 {
		t.Fatalf("bad key: %v", err)
	}
	var mk [32]byte
	copy(mk[:], rawKey)

	f, err := os.Open(v2Path)
	if err != nil {
		t.Fatalf("open v2: %v", err)
	}
	defer f.Close()

	var out bytes.Buffer
	if _, err := UnsealVspk3V2Stream(mk, "backend", "svc-v2-stream", "prod-cluster", f, &out); err != nil {
		t.Fatalf("UnsealVspk3V2Stream failed: %v", err)
	}
	if out.String() != "POLYGLOT_VSPK3_V2_STREAM_RUST_TO_GO_2026_OK" {
		t.Fatalf("unexpected v2 plaintext: %q", out.String())
	}
}

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
	if _, err := p.UnsealActionVspk3("cfg.read.v3", validArgs, "wrong-asset", blob); !errors.Is(err, ErrVaultAuthFailed) {
		t.Fatal("expected wrong assetId to fail with ErrVaultAuthFailed")
	}
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0x55
	if _, err := p.UnsealActionVspk3("cfg.read.v3", validArgs, "svc-secrets-v3", tampered); !errors.Is(err, ErrVaultAuthFailed) {
		t.Fatal("expected tampered ciphertext to fail with ErrVaultAuthFailed")
	}
	pWrong := *p
	pWrong.MasterKey[0] ^= 0x01
	if _, err := pWrong.UnsealActionVspk3("cfg.read.v3", validArgs, "svc-secrets-v3", blob); !errors.Is(err, ErrVaultAuthFailed) {
		t.Fatal("expected wrong key to fail with ErrVaultAuthFailed")
	}
}
