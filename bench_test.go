package catena

// The benchmark tests run through garlics of 16-20. The starting value
// of 16 was chosen based on a recommendation in the Catena paper; the
// tests were run on a machine until the garlic caused the benchmark to
// run for more than ten seconds. This happened to occur with a garlic
// of 21, so these benchmarks stop at a garlic of 20.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

func BenchmarkBasicHash16(b *testing.B) {
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

func BenchmarkBasicHash17(b *testing.B) {
	for i := 0; i < b.N; i++ {
		H := sha256.New()
		testPass := "password"
		tweak, err := Tweak(ModePassHash, H, 16, nil)
		checkBenchErr(b, err)

		garlic := int64(17)
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

func BenchmarkBasicHash18(b *testing.B) {
	for i := 0; i < b.N; i++ {
		H := sha256.New()
		testPass := "password"
		tweak, err := Tweak(ModePassHash, H, 16, nil)
		checkBenchErr(b, err)

		garlic := int64(18)
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

func BenchmarkBasicHash19(b *testing.B) {
	for i := 0; i < b.N; i++ {
		H := sha256.New()
		testPass := "password"
		tweak, err := Tweak(ModePassHash, H, 16, nil)
		checkBenchErr(b, err)

		garlic := int64(19)
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

func BenchmarkBasicHash20(b *testing.B) {
	for i := 0; i < b.N; i++ {
		H := sha256.New()
		testPass := "password"
		tweak, err := Tweak(ModePassHash, H, 16, nil)
		checkBenchErr(b, err)

		garlic := int64(20)
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
