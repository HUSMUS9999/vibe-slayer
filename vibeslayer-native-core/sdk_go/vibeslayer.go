package vibeslayer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
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
		return nil, errors.New("BAD_TAG_LEN")
	}
	if len(ct) > 0 && (uint64(len(ct)-1)/64) >= uint64(math.MaxUint32-1) {
		return nil, errors.New("CHACHA20_COUNTER_OVERFLOW")
	}
	blk0 := chacha20Block(key, 0, nonce)
	var otk [32]byte
	copy(otk[:], blk0[:32])
	zeroBytes(blk0[:])

	expected := poly1305Mac(otk, aad, ct)
	zeroBytes(otk[:])
	if subtle.ConstantTimeCompare(expected[:], tag) != 1 {
		return nil, errors.New("AEAD_AUTH_FAILED")
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

func encodeCanonicalVspk3Info(domain, assetID, context string) []byte {
	info := make([]byte, 0, 10+12+len(domain)+len(assetID)+len(context))
	info = append(info, []byte("VSPK3_CMT4")...)
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
	return info
}

func (p *Policy) UnsealActionVspk2(action string, args map[string]any, vspk []byte) ([]byte, error) {
	act, err := p.ValidateAction(action, args)
	if err != nil {
		return nil, err
	}
	if len(vspk) < 40 || string(vspk[0:5]) != "VSPK2" || vspk[5] != 1 {
		return nil, errors.New("BAD_VSPK2_HEADER")
	}
	dlen := int(binary.LittleEndian.Uint16(vspk[6:8]))
	alen := int(binary.LittleEndian.Uint16(vspk[8:10]))
	clen := int(binary.LittleEndian.Uint16(vspk[10:12]))
	if dlen > 128 || alen > 128 || clen > 256 {
		return nil, errors.New("BAD_VSPK2_HEADER_BOUNDS")
	}
	hdrEnd := 40 + dlen + alen + clen
	if len(vspk) < hdrEnd {
		return nil, errors.New("TRUNCATED_VSPK2")
	}
	domBytes := vspk[40 : 40+dlen]
	aidBytes := vspk[40+dlen : 40+dlen+alen]
	ctxBytes := vspk[40+dlen+alen : hdrEnd]
	if bytes.IndexByte(domBytes, 0) >= 0 || bytes.IndexByte(aidBytes, 0) >= 0 || bytes.IndexByte(ctxBytes, 0) >= 0 {
		return nil, errors.New("MALFORMED_VSPK2_NUL")
	}
	domain := string(domBytes)
	assetID := string(aidBytes)
	context := string(ctxBytes)
	if domain != act.Domain || context != act.Context {
		return nil, errors.New("CONTEXT_OR_DOMAIN_DENIED")
	}
	if act.AssetID != "" && assetID != act.AssetID {
		return nil, errors.New("ASSET_ID_DENIED")
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
		return nil, errors.New("ASSET_ID_DENIED")
	}
	if len(vspk) < prefixLen+padQuantum {
		return nil, errors.New("TRUNCATED_VSPK3")
	}
	ct := vspk[prefixLen:]
	if len(ct)%padQuantum != 0 {
		return nil, errors.New("UNALIGNED_VSPK3_CIPHERTEXT")
	}

	salt := vspk[0:32]
	var nonce [12]byte
	copy(nonce[:], vspk[32:44])
	cmt4 := vspk[44:76]
	tag := vspk[76:92]

	info := encodeCanonicalVspk3Info(act.Domain, assetID, act.Context)
	defer zeroBytes(info)

	encInfo := make([]byte, 0, len(info)+4)
	encInfo = append(encInfo, info...)
	encInfo = append(encInfo, []byte("|ENC")...)
	cmtInfo := make([]byte, 0, len(info)+4)
	cmtInfo = append(cmtInfo, info...)
	cmtInfo = append(cmtInfo, []byte("|CMT")...)

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
		return nil, errors.New("CMT4_COMMITMENT_FAILED")
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
		return nil, err
	}
	defer zeroBytes(inner)

	if len(inner) < 4 || len(inner)%padQuantum != 0 {
		return nil, errors.New("INVALID_VSPK3_PADDING")
	}
	plainLen := binary.LittleEndian.Uint32(inner[0:4])
	if uint64(plainLen) > uint64(len(inner)-4) {
		return nil, errors.New("CORRUPT_VSPK3_LENGTH")
	}
	out := make([]byte, int(plainLen))
	copy(out, inner[4:4+int(plainLen)])
	return out, nil
}
