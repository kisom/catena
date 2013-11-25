package catena

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"os"
	"testing"
)

type rBitTest struct {
	Value    uint32
	Expected uint32
}

var rBitTests = []rBitTest{
	rBitTest{0x1, 0x80000000},
	rBitTest{0x10, 0x8000000},
	rBitTest{0x100, 0x800000},
	rBitTest{0x1000, 0x080000},
	rBitTest{0x10000, 0x8000},
	rBitTest{0x1000000, 0x80},
	rBitTest{0x10000000, 0x8},
	rBitTest{0xabcdef01, 0x80f7b3d5},
}

func TestReverseBits(t *testing.T) {
	for i, tc := range rBitTests {
		actual := reverseBits(tc.Value)
		if actual != tc.Expected {
			fmt.Fprintf(os.Stderr,
				"Test %d failed: expected %x, saw %x\n",
				i, tc.Expected, actual)
			t.FailNow()
		}
	}
}

type tweakTest struct {
	Mode     byte
	H        hash.Hash
	SaltLen  int
	AD       []byte
	Expected []byte
}

var tweakTests = []tweakTest{
	tweakTest{ModeKeyDerivation, sha256.New(), 16, nil,
		[]byte{0x01, 0x01, 0x00, 0x00, 0x80, 0xe3, 0xb0, 0xc4,
			0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
			0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41,
			0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99,
			0x1b, 0x78, 0x52, 0xb8, 0x55}},
}

func TestTweakGeneration(t *testing.T) {
	for _, tc := range tweakTests {
		tweak, err := Tweak(tc.Mode, tc.H, tc.SaltLen, tc.AD)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			t.FailNow()
		}

		if !bytes.Equal(tweak, tc.Expected) {
			fmt.Fprintf(os.Stderr, "catena: Tweak didn't produce expected tweak\n")
			fmt.Fprintf(os.Stderr, "\tExpected: %x\n", tc.Expected)
			fmt.Fprintf(os.Stderr, "\t  Actual: %x\n", tweak)
			t.FailNow()
		}
	}
}
