package catena

import (
	"errors"
	"hash"
	"math/big"
)

const cPad = 4

const (
	ModePassHash      byte = 0x00
	ModeKeyDerivation byte = 0x01
)

var twoTo32m1 = new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
var (
	ErrInvalidGarlic    = errors.New("catena: invalid garlic")
	ErrInvalidTweakMode = errors.New("catena: invalid tweak mode")
)

// Algorithm from Hacker's Delight
func reverseBits(x uint32) uint32 {
	x = (x&0x55555555)<<1 | (x&0xAAAAAAAA)>>1
	x = (x&0x33333333)<<2 | (x&0xCCCCCCCC)>>2
	x = (x&0x0F0F0F0F)<<4 | (x&0xF0F0F0F0)>>4
	x = (x&0x00FF00FF)<<8 | (x&0xFF00FF00)>>8
	return (x&0x0000FFFF)<<16 | (x&0xFFFF0000)>>16
}

func incCounter(ctr *[4]byte) {
	if ctr[3]++; ctr[3] != 0 {
		return
	} else if ctr[2]++; ctr[2] != 0 {
		return
	} else if ctr[1]++; ctr[1] != 0 {
		return
	} else if ctr[0]++; ctr[0] != 0 {
		return
	}
	return
}

func bigPadded(n *big.Int, padLen int) []byte {
	in := n.Bytes()
	var inLen int
	if inLen = len(in); inLen > padLen {
		inLen = padLen
	} else if inLen == padLen {
		return in
	}
	start := padLen - inLen
	out := make([]byte, padLen)
	copy(out[start:], in)
	return out
}

func sbrh(c, x []byte, H hash.Hash) ([]byte, error) {
	var counter [4]byte

	garlic := new(big.Int).SetBytes(c)
	if garlic.Cmp(twoTo32m1) > 0 {
		return nil, ErrInvalidGarlic
	}

	var twoToC = new(big.Int).Exp(big.NewInt(2), garlic, nil)
	var stop = int(twoToC.Int64())
	var v = make([][]byte, stop)

	H.Write(c)
	H.Write(counter[:])
	H.Write(x)
	v[0] = H.Sum(nil)
	H.Reset()

	for i := 1; i < stop; i++ {
		H.Write(c)
		incCounter(&counter)
		H.Write(counter[:])
		H.Write(v[i-1])
		v[i] = H.Sum(nil)
		H.Reset()
	}

	H.Write(c)
	H.Write(bigPadded(twoToC, cPad))
	H.Write(v[0])
	H.Write(v[stop-1])
	x2 := H.Sum(nil)
	H.Reset()

	for i := 1; i < stop; i++ {
		j := reverseBits(uint32(i))
		H.Write(c)
		ci := new(big.Int).Add(twoToC, big.NewInt(int64(i)))
		H.Write(bigPadded(ci, cPad))
		H.Write(x2)
		H.Write(v[int(j)])
		x2 = H.Sum(nil)
	}

	return x2, nil
}

func Tweak(mode byte, H hash.Hash, saltLen int, ad []byte) ([]byte, error) {
	if mode != ModePassHash && mode != ModeKeyDerivation {
		return nil, ErrInvalidTweakMode
	}

	hashLen := H.Size()
	tweakLen := 5 + hashLen
	var t = make([]byte, 1, tweakLen)
	t[0] = mode

	var tmp uint16 = uint16(H.Size() * 8)
	high := byte(tmp >> 8)
	low := byte(tmp << 8 >> 8)
	t = append(t, high)
	t = append(t, low)

	tmp = uint16(saltLen * 8)
	high = byte(tmp >> 8)
	low = byte(tmp << 8 >> 8)
	t = append(t, high)
	t = append(t, low)

	H.Reset()
	H.Write(ad)
	t = append(t, H.Sum(nil)...)
	H.Reset()
	return t, nil
}

func HashPasswordWithSalt(password, tweak, salt []byte, g, g0 int64, H hash.Hash) ([]byte, error) {
	if g < g0 {
		return ErrInvalidGarlic
	}

	x := make([]byte, len(tweak)+len(password)|len(salt))
	copy(x, tweak)
	copy(x[len(tweak):], password)
	copy(x[len(tweak)+len(password):], salt)

	var err error
	for i := g0; i < g; i++ {
		c := bigPadded(big.NewInt(i), cPad)
		twoCp1 := new(big.Int).Exp(big.NewInt(2), big.NewInt(i), nil)
		twoCp1 = twoCp1.Add(twoCp1, big.NewInt(1))
		x, err = sbrh(c, x, H)
		if err != nil {
			H.Reset()
			return err
		}
		H.Write(c)
		H.Write(bigPadded(twoCp1, cPad))
		H.Write(x)
		x = H.Sum(nil)
		H.Reset()
	}
	return nil
}