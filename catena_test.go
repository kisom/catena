package catena

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	// sha256 "github.com/conformal/fastsha256"
	"hash"
	"os"
	"testing"
)

func checkErr(t *testing.T, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		t.FailNow()
	}
}

func checkBenchErr(b *testing.B, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		b.FailNow()
	}
}

type rBitTest struct {
	Value    uint32
	Expected int
}

var rBitTests = []rBitTest{
	rBitTest{0x1, 0x1},
	rBitTest{0x10, 0x1},
	rBitTest{0x100, 0x1},
	rBitTest{0x1000, 0x1},
	rBitTest{0x10000, 0x1},
	rBitTest{0x1000000, 0x1},
	rBitTest{0x10000000, 0x1},
	rBitTest{0xabcdef01, 2163717077},
}

func TestReverseBits(t *testing.T) {
	for i, tc := range rBitTests {
		actual := tau(tc.Value)
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

func TestBasicHash(t *testing.T) {
	H := sha256.New()
	testPass := "password"
	tweak, err := Tweak(ModePassHash, H, 16, nil)
	checkErr(t, err)

	garlic := int64(16)
	ph, err := HashPassword([]byte(testPass), tweak, garlic, garlic, H, 16)
	checkErr(t, err)

	if !MatchPassword([]byte(testPass), tweak, garlic, garlic, H, ph) {
		fmt.Fprintf(os.Stderr, "catena: failed to match password\n")
		t.FailNow()
	}
}

func TestBasicHashNoTweak(t *testing.T) {
	H := sha256.New()
	testPass := "password"

	garlic := int64(16)
	ph, err := HashPassword([]byte(testPass), nil, garlic, garlic, H, 16)
	checkErr(t, err)

	if !MatchPassword([]byte(testPass), nil, garlic, garlic, H, ph) {
		fmt.Fprintf(os.Stderr, "catena: failed to match password\n")
		t.FailNow()
	}
}

func TestBasicHashFailsGarlic(t *testing.T) {
	H := sha256.New()
	testPass := "password"
	tweak, err := Tweak(ModePassHash, H, 16, nil)
	checkErr(t, err)

	garlic := int64(16)
	ph, err := HashPassword([]byte(testPass), tweak, garlic, garlic, H, 16)
	checkErr(t, err)

	if MatchPassword([]byte(testPass), tweak, garlic-2, garlic-2, H, ph) {
		fmt.Fprintf(os.Stderr, "catena: failed to match password\n")
		t.FailNow()
	}
}

func TestBasicHashFailsPassword(t *testing.T) {
	H := sha256.New()
	testPass := "password1"
	badPass := "password2"
	tweak, err := Tweak(ModePassHash, H, 16, nil)
	checkErr(t, err)

	garlic := int64(16)
	ph, err := HashPassword([]byte(testPass), tweak, garlic, garlic, H, 16)
	checkErr(t, err)

	if MatchPassword([]byte(badPass), tweak, garlic, garlic, H, ph) {
		fmt.Fprintf(os.Stderr, "catena: failed to match password\n")
		t.FailNow()
	}
}

func BenchmarkBasicHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		H := sha256.New()
		testPass := "password"
		tweak, err := Tweak(ModePassHash, H, 16, nil)
		checkBenchErr(b, err)

		garlic := int64(16)
		ph, err := HashPassword([]byte(testPass), tweak, garlic, garlic, H, 16)
		checkBenchErr(b, err)

		hash, err := HashPasswordWithSalt([]byte(testPass), tweak, ph.Salt, garlic, garlic, H)
		checkBenchErr(b, err)

		if !bytes.Equal(hash, ph.Hash) {
			fmt.Fprintf(os.Stderr, "catena: failed to match password in bench\n")
			b.FailNow()
		}
	}
}
