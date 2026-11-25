package vibeslayer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
)

// ErrVaultAuthFailed is the single unified opaque authentication error returned on any
// commitment, AEAD tag, chunk counter, or final-chunk padding/length failure.
var ErrVaultAuthFailed = errors.New("VAULT_AUTH_FAILED")

const (
	Vspk3V2PrefixLen             = 64
	Vspk3V2ChunkPlain            = 65536
	Vspk3V2PadQuantum            = 1024
	Vspk3V2TrailerLen            = 48
	Vspk3V2IntermediateRecordLen = Vspk3V2ChunkPlain + Vspk3V2TrailerLen
	vspk3V2MinFinalRecordLen     = Vspk3V2PadQuantum + Vspk3V2TrailerLen
	vspk3V2MaxFinalRecordLen     = (((4 + Vspk3V2ChunkPlain + Vspk3V2PadQuantum - 1) / Vspk3V2PadQuantum) * Vspk3V2PadQuantum) + Vspk3V2TrailerLen
	vspk3V2MinTwoChunksLen       = Vspk3V2IntermediateRecordLen + vspk3V2MinFinalRecordLen
	vspk3V2MaxAesGcmChunks       = (uint64(1) << 32) - 1
)

type ParamKind string

const (
	ParamInt  ParamKind = "int"
	ParamEnum ParamKind = "enum"
	ParamStr  ParamKind = "str"
	ParamBool ParamKind = "bool"
)

type ParamRule struct {
	Kind   ParamKind
	Min    int64
	Max    int64
	Values []string
}

type ActionRule struct {
	Domain  string
	Context string
	AssetID string
	Params  map[string]ParamRule
}

type Policy struct {
	Enabled   bool
	MasterKey [32]byte
	Actions   map[string]ActionRule
}

func (p *Policy) ValidateAction(name string, args map[string]any) (*ActionRule, error) {
	if !p.Enabled {
		return nil, errors.New("POLICY_DISABLED")
	}
	act, ok := p.Actions[name]
	if !ok {
		return nil, fmt.Errorf("UNKNOWN_ACTION:%s", name)
	}
	for k := range args {
		if _, exists := act.Params[k]; !exists {
			return nil, fmt.Errorf("UNKNOWN_PARAM:%s", k)
		}
	}
	for pName, rule := range act.Params {
		val, exists := args[pName]
		if !exists {
			return nil, fmt.Errorf("MISSING_PARAM:%s", pName)
		}
		switch rule.Kind {
		case ParamInt:
			iv, ok := val.(int64)
			if !ok {
				return nil, fmt.Errorf("BAD_PARAM_TYPE:%s", pName)
			}
			if iv < rule.Min || iv > rule.Max {
				return nil, fmt.Errorf("PARAM_OUT_OF_RANGE:%s", pName)
			}
		case ParamEnum:
			sv, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("BAD_PARAM_TYPE:%s", pName)
			}
			matched := false
			for _, allowed := range rule.Values {
				if allowed == sv {
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("PARAM_OUT_OF_RANGE:%s", pName)
			}
		case ParamStr:
			if _, ok := val.(string); !ok {
				return nil, fmt.Errorf("BAD_PARAM_TYPE:%s", pName)
			}
		case ParamBool:
			if _, ok := val.(bool); !ok {
				return nil, fmt.Errorf("BAD_PARAM_TYPE:%s", pName)
			}
		default:
			return nil, fmt.Errorf("UNSUPPORTED_PARAM_KIND:%s", pName)
		}
	}
	return &act, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func hkdfSha256_32(ikm, salt, info []byte) [32]byte {
	prkMac := hmac.New(sha256.New, salt)
	prkMac.Write(ikm)
	prk := prkMac.Sum(nil)

	okmMac := hmac.New(sha256.New, prk)
	okmMac.Write(info)
	okmMac.Write([]byte{1})
	var out [32]byte
	copy(out[:], okmMac.Sum(nil))
	zeroBytes(prk)
	return out
}

func encodeCanonicalInfo(tag, domain, assetID, context string) ([]byte, error) {
	if len(domain) > 4096 || len(assetID) > 4096 || len(context) > 4096 {
		return nil, errors.New("INVALID_METADATA")
	}
	info := make([]byte, 0, len(tag)+12+len(domain)+len(assetID)+len(context))
	info = append(info, tag...)
	var le [4]byte
	binary.LittleEndian.PutUint32(le[:], uint32(len(domain)))
	info = append(info, le[:]...)
	info = append(info, domain...)
	binary.LittleEndian.PutUint32(le[:], uint32(len(assetID)))
	info = append(info, le[:]...)
	info = append(info, assetID...)
	binary.LittleEndian.PutUint32(le[:], uint32(len(context)))
	info = append(info, le[:]...)
	info = append(info, context...)
	return info, nil
}

// ==================== VSPK3 v2 64-BIT STREAM (AUDITED GO STDLIB AES-256-GCM) ====================

func v2StreamNonce(chunkIndex uint64, isFinal bool) [12]byte {
	var nonce [12]byte
	if isFinal {
		nonce[3] = 0x01
	}
	binary.BigEndian.PutUint64(nonce[4:12], chunkIndex)
	return nonce
}

func deriveV2SubkeysAesGcm(masterKey [32]byte, salt [32]byte, info []byte) (encKey [32]byte, cmtKey [32]byte, hdrCmt [32]byte) {
	const algTag = "|AES256GCM"
	encInfo := make([]byte, 0, len(info)+len(algTag)+4)
	encInfo = append(encInfo, info...)
	encInfo = append(encInfo, algTag...)
	encInfo = append(encInfo, "|ENC"...)

	cmtInfo := make([]byte, 0, len(info)+len(algTag)+4)
	cmtInfo = append(cmtInfo, info...)
	cmtInfo = append(cmtInfo, algTag...)
	cmtInfo = append(cmtInfo, "|CMT"...)

	encKey = hkdfSha256_32(masterKey[:], salt[:], encInfo)
	cmtKey = hkdfSha256_32(masterKey[:], salt[:], cmtInfo)
	zeroBytes(encInfo)
	zeroBytes(cmtInfo)

	mac := hmac.New(sha256.New, cmtKey[:])
	mac.Write([]byte("VSPK3_V2_HDR|"))
	mac.Write(salt[:])
	mac.Write([]byte(algTag))
	mac.Write(info)
	copy(hdrCmt[:], mac.Sum(nil))
	return encKey, cmtKey, hdrCmt
}

func v2ChunkCtxCommitment(cmtKey [32]byte, salt [32]byte, nonce [12]byte, info []byte, chunkIndex uint64, isFinal bool, tag []byte) [32]byte {
	var flag [1]byte
	if isFinal {
		flag[0] = 1
	}
	var idxBe [8]byte
	binary.BigEndian.PutUint64(idxBe[:], chunkIndex)
	mac := hmac.New(sha256.New, cmtKey[:])
	mac.Write([]byte("VSPK3_V2_CTX|"))
	mac.Write(salt[:])
	mac.Write(nonce[:])
	mac.Write(idxBe[:])
	mac.Write(flag[:])
	mac.Write(info)
	mac.Write(tag)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func v2ChunkAad(salt [32]byte, hdrCmt [32]byte, chunkIndex uint64, isFinal bool, info []byte) []byte {
	aad := make([]byte, 0, 64+9+len(info))
	aad = append(aad, salt[:]...)
	aad = append(aad, hdrCmt[:]...)
	var idxBe [8]byte
	binary.BigEndian.PutUint64(idxBe[:], chunkIndex)
	aad = append(aad, idxBe[:]...)
	if isFinal {
		aad = append(aad, 1)
	} else {
		aad = append(aad, 0)
	}
	aad = append(aad, info...)
	return aad
}

func readUpTo(r io.Reader, buf []byte) (int, error) {
	filled := 0
	for filled < len(buf) {
		n, err := r.Read(buf[filled:])
		filled += n
		if err == io.EOF {
			break
		}
		if err != nil {
			return filled, err
		}
	}
	return filled, nil
}

// SealVspk3V2Stream stream-seals arbitrary-size input (up to 256 TiB) in constant ~132 KiB RAM
// using Go stdlib hardware-accelerated AES-256-GCM + Bellare-Hoang Ctx/UtC CMT-4 commitment,
// bit-for-bit wire-compatible with Rust `vs-vault` (`AeadAlg::Aes256Gcm`).
func SealVspk3V2Stream(masterKey [32]byte, domain, assetID, context string, r io.Reader, w io.Writer) (int64, error) {
	info, err := encodeCanonicalInfo("VSPK3_V2_STREAM", domain, assetID, context)
	if err != nil {
		return 0, err
	}
	defer zeroBytes(info)

	var salt [32]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return 0, err
	}
	encKey, cmtKey, hdrCmt := deriveV2SubkeysAesGcm(masterKey, salt, info)
	defer zeroBytes(encKey[:])
	defer zeroBytes(cmtKey[:])

	block, err := aes.NewCipher(encKey[:])
	if err != nil {
		return 0, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return 0, err
	}

	if _, err := w.Write(salt[:]); err != nil {
		return 0, err
	}
	if _, err := w.Write(hdrCmt[:]); err != nil {
		return 0, err
	}
	var totalWritten int64 = Vspk3V2PrefixLen

	buf := make([]byte, Vspk3V2ChunkPlain+1)
	defer zeroBytes(buf)
	hasCarried := false
	var carried byte
	var chunkIndex uint64

	const maxChunks uint64 = (1 << 32) - 1

	for {
		start := 0
		if hasCarried {
			buf[0] = carried
			start = 1
			hasCarried = false
		}
		n, err := readUpTo(r, buf[start:])
		if err != nil {
			return totalWritten, err
		}
		filled := start + n

		if filled > Vspk3V2ChunkPlain {
			if chunkIndex >= maxChunks {
				return totalWritten, ErrVaultAuthFailed
			}
			nonce := v2StreamNonce(chunkIndex, false)
			aad := v2ChunkAad(salt, hdrCmt, chunkIndex, false, info)
			sealed := aead.Seal(nil, nonce[:], buf[:Vspk3V2ChunkPlain], aad)
			ct := sealed[:Vspk3V2ChunkPlain]
			tag := sealed[Vspk3V2ChunkPlain:]
			ctxCmt := v2ChunkCtxCommitment(cmtKey, salt, nonce, info, chunkIndex, false, tag)

			if _, err := w.Write(ct); err != nil {
				return totalWritten, err
			}
			if _, err := w.Write(tag); err != nil {
				return totalWritten, err
			}
			if _, err := w.Write(ctxCmt[:]); err != nil {
				return totalWritten, err
			}
			totalWritten += int64(len(ct) + Vspk3V2TrailerLen)

			carried = buf[Vspk3V2ChunkPlain]
			hasCarried = true
			chunkIndex++
			continue
		}

		unpaddedLen := 4 + filled
		paddedLen := ((unpaddedLen + Vspk3V2PadQuantum - 1) / Vspk3V2PadQuantum) * Vspk3V2PadQuantum
		finalPlain := make([]byte, paddedLen)
		binary.LittleEndian.PutUint32(finalPlain[0:4], uint32(filled))
		copy(finalPlain[4:4+filled], buf[:filled])

		nonce := v2StreamNonce(chunkIndex, true)
		aad := v2ChunkAad(salt, hdrCmt, chunkIndex, true, info)
		sealed := aead.Seal(nil, nonce[:], finalPlain, aad)
		zeroBytes(finalPlain)
		ct := sealed[:paddedLen]
		tag := sealed[paddedLen:]
		ctxCmt := v2ChunkCtxCommitment(cmtKey, salt, nonce, info, chunkIndex, true, tag)

		if _, err := w.Write(ct); err != nil {
			return totalWritten, err
		}
		if _, err := w.Write(tag); err != nil {
			return totalWritten, err
		}
		if _, err := w.Write(ctxCmt[:]); err != nil {
			return totalWritten, err
		}
		totalWritten += int64(len(ct) + Vspk3V2TrailerLen)
		break
	}
	return totalWritten, nil
}

// UnsealVspk3V2Stream stream-unseals a VSPK3 v2 AES-256-GCM vault in constant ~132 KiB RAM,
// returning the unified opaque `ErrVaultAuthFailed` on any cryptographic or framing failure.
func UnsealVspk3V2Stream(masterKey [32]byte, domain, assetID, context string, r io.Reader, w io.Writer) (int64, error) {
	info, err := encodeCanonicalInfo("VSPK3_V2_STREAM", domain, assetID, context)
	if err != nil {
		return 0, ErrVaultAuthFailed
	}
	defer zeroBytes(info)

	var prefix [Vspk3V2PrefixLen]byte
	if n, err := readUpTo(r, prefix[:]); err != nil || n != Vspk3V2PrefixLen {
		return 0, ErrVaultAuthFailed
	}
	var salt, hdrCmt [32]byte
	copy(salt[:], prefix[0:32])
	copy(hdrCmt[:], prefix[32:64])

	encKey, cmtKey, expectedHdr := deriveV2SubkeysAesGcm(masterKey, salt, info)
	defer zeroBytes(encKey[:])
	defer zeroBytes(cmtKey[:])
	if subtle.ConstantTimeCompare(hdrCmt[:], expectedHdr[:]) != 1 {
		return 0, ErrVaultAuthFailed
	}

	block, err := aes.NewCipher(encKey[:])
	if err != nil {
		return 0, ErrVaultAuthFailed
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return 0, ErrVaultAuthFailed
	}

	window := make([]byte, vspk3V2MinTwoChunksLen)
	defer zeroBytes(window)
	buffered := 0
	var chunkIndex uint64
	var totalPlain int64

	for {
		if buffered < len(window) {
			n, err := readUpTo(r, window[buffered:])
			if err != nil {
				return 0, err
			}
			buffered += n
		}
		if buffered < vspk3V2MinFinalRecordLen || (buffered > vspk3V2MaxFinalRecordLen && buffered < vspk3V2MinTwoChunksLen) {
			return 0, ErrVaultAuthFailed
		}

		isFinal := buffered <= vspk3V2MaxFinalRecordLen
		if !isFinal {
			if chunkIndex >= vspk3V2MaxAesGcmChunks {
				return 0, ErrVaultAuthFailed
			}
			rec := window[:Vspk3V2IntermediateRecordLen]
			ctAndTag := rec[:Vspk3V2ChunkPlain+16]
			tag := rec[Vspk3V2ChunkPlain : Vspk3V2ChunkPlain+16]
			ctxCmt := rec[Vspk3V2ChunkPlain+16:]

			nonce := v2StreamNonce(chunkIndex, false)
			expectedCtx := v2ChunkCtxCommitment(cmtKey, salt, nonce, info, chunkIndex, false, tag)
			if subtle.ConstantTimeCompare(ctxCmt, expectedCtx[:]) != 1 {
				return 0, ErrVaultAuthFailed
			}
			aad := v2ChunkAad(salt, hdrCmt, chunkIndex, false, info)
			plain, err := aead.Open(nil, nonce[:], ctAndTag, aad)
			if err != nil {
				return 0, ErrVaultAuthFailed
			}
			nw, werr := w.Write(plain)
			zeroBytes(plain)
			if werr != nil {
				return 0, werr
			}
			totalPlain += int64(nw)

			remain := buffered - Vspk3V2IntermediateRecordLen
			copy(window[:remain], window[Vspk3V2IntermediateRecordLen:buffered])
			buffered = remain
			chunkIndex++
		} else {
			if chunkIndex > vspk3V2MaxAesGcmChunks {
				return 0, ErrVaultAuthFailed
			}
			ctLen := buffered - Vspk3V2TrailerLen
			if ctLen < Vspk3V2PadQuantum || ctLen%Vspk3V2PadQuantum != 0 {
				return 0, ErrVaultAuthFailed
			}
			ctAndTag := window[:ctLen+16]
			tag := window[ctLen : ctLen+16]
			ctxCmt := window[ctLen+16 : buffered]

			nonce := v2StreamNonce(chunkIndex, true)
			expectedCtx := v2ChunkCtxCommitment(cmtKey, salt, nonce, info, chunkIndex, true, tag)
			if subtle.ConstantTimeCompare(ctxCmt, expectedCtx[:]) != 1 {
				return 0, ErrVaultAuthFailed
			}
			aad := v2ChunkAad(salt, hdrCmt, chunkIndex, true, info)
			plain, err := aead.Open(nil, nonce[:], ctAndTag, aad)
			if err != nil {
				return 0, ErrVaultAuthFailed
			}
			defer zeroBytes(plain)
			if len(plain) < 4 {
				return 0, ErrVaultAuthFailed
			}
			remLenU32 := binary.LittleEndian.Uint32(plain[0:4])
			if remLenU32 > Vspk3V2ChunkPlain || uint64(4)+uint64(remLenU32) > uint64(len(plain)) {
				return 0, ErrVaultAuthFailed
			}
			remLen := int(remLenU32)
			var padOr byte
			for _, b := range plain[4+remLen:] {
				padOr |= b
			}
			if padOr != 0 {
				return 0, ErrVaultAuthFailed
			}
			nw, werr := w.Write(plain[4 : 4+remLen])
			if werr != nil {
				return 0, werr
			}
			totalPlain += int64(nw)
			break
		}
	}
	return totalPlain, nil
}

// SealVspk3V2 convenience in-memory wrapper around SealVspk3V2Stream.
func SealVspk3V2(masterKey [32]byte, domain, assetID, context string, plaintext []byte) ([]byte, error) {
	var out bytes.Buffer
	if _, err := SealVspk3V2Stream(masterKey, domain, assetID, context, bytes.NewReader(plaintext), &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// UnsealVspk3V2 convenience in-memory wrapper around UnsealVspk3V2Stream (zeroizes partial output on error).
func UnsealVspk3V2(masterKey [32]byte, domain, assetID, context string, container []byte) ([]byte, error) {
	var out bytes.Buffer
	if _, err := UnsealVspk3V2Stream(masterKey, domain, assetID, context, bytes.NewReader(container), &out); err != nil {
		zeroBytes(out.Bytes())
		out.Reset()
		return nil, err
	}
	return out.Bytes(), nil
}

// UnsealActionVspk3V2 enforces Policy bounds and unseals a VSPK3 v2 AES-256-GCM stream.
func (p *Policy) UnsealActionVspk3V2(action string, args map[string]any, assetID string, r io.Reader, w io.Writer) (int64, error) {
	act, err := p.ValidateAction(action, args)
	if err != nil {
		return 0, err
	}
	if act.AssetID != "" && assetID != act.AssetID {
		return 0, ErrVaultAuthFailed
	}
	return UnsealVspk3V2Stream(p.MasterKey, act.Domain, assetID, act.Context, r, w)
}

// ==================== LEGACY VSPK2 & VSPK3 v1 COMPATIBILITY ====================

func qr(x *[16]uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] = bits.RotateLeft32(x[d]^x[a], 16)
	x[c] += x[d]
	x[b] = bits.RotateLeft32(x[b]^x[c], 12)
	x[a] += x[b]
	x[d] = bits.RotateLeft32(x[d]^x[a], 8)
	x[c] += x[d]
	x[b] = bits.RotateLeft32(x[b]^x[c], 7)
}

func chacha20Block(key [32]byte, counter uint32, nonce [12]byte) [64]byte {
	var s [16]uint32
	s[0] = 0x61707865
	s[1] = 0x3320646e
	s[2] = 0x79622d32
	s[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}
	s[12] = counter
	for i := 0; i < 3; i++ {
		s[13+i] = binary.LittleEndian.Uint32(nonce[i*4 : i*4+4])
	}
	x := s
	for i := 0; i < 10; i++ {
		qr(&x, 0, 4, 8, 12)
		qr(&x, 1, 5, 9, 13)
		qr(&x, 2, 6, 10, 14)
		qr(&x, 3, 7, 11, 15)
		qr(&x, 0, 5, 10, 15)
		qr(&x, 1, 6, 11, 12)
		qr(&x, 2, 7, 8, 13)
		qr(&x, 3, 4, 9, 14)
	}
	var out [64]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:i*4+4], x[i]+s[i])
	}
	return out
}

func poly1305Mac(otk [32]byte, aad, ct []byte) [16]byte {
	r0 := binary.LittleEndian.Uint32(otk[0:4]) & 0x3ffffff
	r1 := (binary.LittleEndian.Uint32(otk[3:7]) >> 2) & 0x3ffff03
	r2 := (binary.LittleEndian.Uint32(otk[6:10]) >> 4) & 0x3ffc0ff
	r3 := (binary.LittleEndian.Uint32(otk[9:13]) >> 6) & 0x3f03fff
	r4 := (binary.LittleEndian.Uint32(otk[12:16]) >> 8) & 0x00fffff

	s1, s2, s3, s4 := r1*5, r2*5, r3*5, r4*5
	var h0, h1, h2, h3, h4 uint32

	feedBlock := func(blk [16]byte) {
		h0 += binary.LittleEndian.Uint32(blk[0:4]) & 0x3ffffff
		h1 += (binary.LittleEndian.Uint32(blk[3:7]) >> 2) & 0x3ffffff
		h2 += (binary.LittleEndian.Uint32(blk[6:10]) >> 4) & 0x3ffffff
		h3 += (binary.LittleEndian.Uint32(blk[9:13]) >> 6) & 0x3ffffff
		h4 += (binary.LittleEndian.Uint32(blk[12:16]) >> 8) | (1 << 24)

		d0 := uint64(h0)*uint64(r0) + uint64(h1)*uint64(s4) + uint64(h2)*uint64(s3) + uint64(h3)*uint64(s2) + uint64(h4)*uint64(s1)
		d1 := uint64(h0)*uint64(r1) + uint64(h1)*uint64(r0) + uint64(h2)*uint64(s4) + uint64(h3)*uint64(s3) + uint64(h4)*uint64(s2)
		d2 := uint64(h0)*uint64(r2) + uint64(h1)*uint64(r1) + uint64(h2)*uint64(r0) + uint64(h3)*uint64(s4) + uint64(h4)*uint64(s3)
		d3 := uint64(h0)*uint64(r3) + uint64(h1)*uint64(r2) + uint64(h2)*uint64(r1) + uint64(h3)*uint64(r0) + uint64(h4)*uint64(s4)
		d4 := uint64(h0)*uint64(r4) + uint64(h1)*uint64(r3) + uint64(h2)*uint64(r2) + uint64(h3)*uint64(r1) + uint64(h4)*uint64(r0)

		c := uint32(d0 >> 26); h0 = uint32(d0) & 0x3ffffff; d1 += uint64(c)
		c = uint32(d1 >> 26); h1 = uint32(d1) & 0x3ffffff; d2 += uint64(c)
		c = uint32(d2 >> 26); h2 = uint32(d2) & 0x3ffffff; d3 += uint64(c)
		c = uint32(d3 >> 26); h3 = uint32(d3) & 0x3ffffff; d4 += uint64(c)
		c = uint32(d4 >> 26); h4 = uint32(d4) & 0x3ffffff; h0 += c * 5
		c = h0 >> 26; h0 &= 0x3ffffff; h1 += c
	}

	for _, part := range [][]byte{aad, ct} {
		for len(part) >= 16 {
			var b [16]byte
			copy(b[:], part[:16])
			feedBlock(b)
			part = part[16:]
		}
		if len(part) > 0 {
			var b [16]byte
			copy(b[:], part)
			feedBlock(b)
		}
	}
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:8], uint64(len(aad)))
	binary.LittleEndian.PutUint64(lens[8:16], uint64(len(ct)))
	feedBlock(lens)

	c := h1 >> 26; h1 &= 0x3ffffff; h2 += c
	c = h2 >> 26; h2 &= 0x3ffffff; h3 += c
	c = h3 >> 26; h3 &= 0x3ffffff; h4 += c
	c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5
	c = h0 >> 26; h0 &= 0x3ffffff; h1 += c

	g0 := h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff
	g1 := h1 + c; c = g1 >> 26; g1 &= 0x3ffffff
	g2 := h2 + c; c = g2 >> 26; g2 &= 0x3ffffff
	g3 := h3 + c; c = g3 >> 26; g3 &= 0x3ffffff
	g4 := h4 + c - (1 << 26)

	mask := (g4 >> 31) - 1
	g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask
	nmask := ^mask
	h0 = (h0 & nmask) | g0
	h1 = (h1 & nmask) | g1
	h2 = (h2 & nmask) | g2
	h3 = (h3 & nmask) | g3
	h4 = (h4 & nmask) | g4

	p0 := uint64(binary.LittleEndian.Uint32(otk[16:20]))
	p1 := uint64(binary.LittleEndian.Uint32(otk[20:24]))
	p2 := uint64(binary.LittleEndian.Uint32(otk[24:28]))
	p3 := uint64(binary.LittleEndian.Uint32(otk[28:32]))

	var mac [16]byte
	f := uint64(h0|(h1<<26)) + p0
	binary.LittleEndian.PutUint32(mac[0:4], uint32(f))
	f = uint64((h1>>6)|(h2<<20)) + p1 + (f >> 32)
	binary.LittleEndian.PutUint32(mac[4:8], uint32(f))
	f = uint64((h2>>12)|(h3<<14)) + p2 + (f >> 32)
	binary.LittleEndian.PutUint32(mac[8:12], uint32(f))
	f = uint64((h3>>18)|(h4<<8)) + p3 + (f >> 32)
	binary.LittleEndian.PutUint32(mac[12:16], uint32(f))
	return mac
}

func chacha20Poly1305Open(key [32]byte, nonce [12]byte, aad, ct []byte, tag []byte) ([]byte, error) {
	if len(tag) != 16 {
		return nil, ErrVaultAuthFailed
	}
	if len(ct) > 0 && (uint64(len(ct)-1)/64) >= uint64(math.MaxUint32-1) {
		return nil, ErrVaultAuthFailed
	}
	blk0 := chacha20Block(key, 0, nonce)
	var otk [32]byte
	copy(otk[:], blk0[:32])
	zeroBytes(blk0[:])

	expected := poly1305Mac(otk, aad, ct)
	zeroBytes(otk[:])
	if subtle.ConstantTimeCompare(expected[:], tag) != 1 {
		return nil, ErrVaultAuthFailed
	}

	out := make([]byte, len(ct))
	ctr := uint32(1)
	for off := 0; off < len(ct); off += 64 {
		blk := chacha20Block(key, ctr, nonce)
		ctr++
		end := off + 64
		if end > len(ct) {
			end = len(ct)
		}
		for i := off; i < end; i++ {
			out[i] = ct[i] ^ blk[i-off]
		}
		zeroBytes(blk[:])
	}
	return out, nil
}

func (p *Policy) UnsealActionVspk2(action string, args map[string]any, vspk []byte) ([]byte, error) {
	act, err := p.ValidateAction(action, args)
	if err != nil {
		return nil, err
	}
	if len(vspk) < 40 || string(vspk[0:5]) != "VSPK2" || vspk[5] != 1 {
		return nil, ErrVaultAuthFailed
	}
	dlen := int(binary.LittleEndian.Uint16(vspk[6:8]))
	alen := int(binary.LittleEndian.Uint16(vspk[8:10]))
	clen := int(binary.LittleEndian.Uint16(vspk[10:12]))
	if dlen > 128 || alen > 128 || clen > 256 {
		return nil, ErrVaultAuthFailed
	}
	hdrEnd := 40 + dlen + alen + clen
	if len(vspk) < hdrEnd {
		return nil, ErrVaultAuthFailed
	}
	domBytes := vspk[40 : 40+dlen]
	aidBytes := vspk[40+dlen : 40+dlen+alen]
	ctxBytes := vspk[40+dlen+alen : hdrEnd]
	if bytes.IndexByte(domBytes, 0) >= 0 || bytes.IndexByte(aidBytes, 0) >= 0 || bytes.IndexByte(ctxBytes, 0) >= 0 {
		return nil, ErrVaultAuthFailed
	}
	domain := string(domBytes)
	assetID := string(aidBytes)
	context := string(ctxBytes)
	if domain != act.Domain || context != act.Context {
		return nil, ErrVaultAuthFailed
	}
	if act.AssetID != "" && assetID != act.AssetID {
		return nil, ErrVaultAuthFailed
	}

	info := []byte(fmt.Sprintf("VSPK2_V1|%s|%s|%s", domain, assetID, context))
	key := hkdfSha256_32(p.MasterKey[:], []byte(assetID), info)
	defer zeroBytes(key[:])
	defer zeroBytes(info)

	var nonce [12]byte
	copy(nonce[:], vspk[12:24])
	return chacha20Poly1305Open(key, nonce, info, vspk[hdrEnd:], vspk[24:40])
}

func (p *Policy) UnsealActionVspk3(action string, args map[string]any, assetID string, vspk []byte) ([]byte, error) {
	const prefixLen = 92
	const padQuantum = 1024
	act, err := p.ValidateAction(action, args)
	if err != nil {
		return nil, err
	}
	if act.AssetID != "" && assetID != act.AssetID {
		return nil, ErrVaultAuthFailed
	}
	if len(vspk) < prefixLen+padQuantum {
		return nil, ErrVaultAuthFailed
	}
	ct := vspk[prefixLen:]
	if len(ct)%padQuantum != 0 {
		return nil, ErrVaultAuthFailed
	}

	salt := vspk[0:32]
	var nonce [12]byte
	copy(nonce[:], vspk[32:44])
	cmt4 := vspk[44:76]
	tag := vspk[76:92]

	info, err := encodeCanonicalInfo("VSPK3_CMT4", act.Domain, assetID, act.Context)
	if err != nil {
		return nil, ErrVaultAuthFailed
	}
	defer zeroBytes(info)

	encInfo := append(append([]byte(nil), info...), []byte("|ENC")...)
	cmtInfo := append(append([]byte(nil), info...), []byte("|CMT")...)

	encKey := hkdfSha256_32(p.MasterKey[:], salt, encInfo)
	cmtKey := hkdfSha256_32(p.MasterKey[:], salt, cmtInfo)
	zeroBytes(encInfo)
	zeroBytes(cmtInfo)
	defer zeroBytes(encKey[:])
	defer zeroBytes(cmtKey[:])

	cmtMac := hmac.New(sha256.New, cmtKey[:])
	cmtMac.Write(nonce[:])
	cmtMac.Write(info)
	expectedCmt4 := cmtMac.Sum(nil)
	zeroBytes(cmtKey[:])
	if subtle.ConstantTimeCompare(expectedCmt4, cmt4) != 1 {
		zeroBytes(expectedCmt4)
		return nil, ErrVaultAuthFailed
	}
	zeroBytes(expectedCmt4)

	aad := make([]byte, 0, 76+len(info))
	aad = append(aad, salt...)
	aad = append(aad, nonce[:]...)
	aad = append(aad, cmt4...)
	aad = append(aad, info...)
	defer zeroBytes(aad)

	inner, err := chacha20Poly1305Open(encKey, nonce, aad, ct, tag)
	if err != nil {
		return nil, ErrVaultAuthFailed
	}
	defer zeroBytes(inner)

	if len(inner) < 4 || len(inner)%padQuantum != 0 {
		return nil, ErrVaultAuthFailed
	}
	plainLenU32 := binary.LittleEndian.Uint32(inner[0:4])
	if uint64(4)+uint64(plainLenU32) > uint64(len(inner)) {
		return nil, ErrVaultAuthFailed
	}
	plainLen := int(plainLenU32)
	var padOr byte
	for _, b := range inner[4+plainLen:] {
		padOr |= b
	}
	if padOr != 0 {
		return nil, ErrVaultAuthFailed
	}
	out := make([]byte, plainLen)
	copy(out, inner[4:4+plainLen])
	return out, nil
}
