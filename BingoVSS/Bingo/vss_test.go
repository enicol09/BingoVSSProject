package vss

import (
	kzg "BingoVSS/Internal/Biv_KZG"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/drand/kyber"
	"github.com/stretchr/testify/require"
)

// func TestRandomMultiple(t *testing.T) {

// 	for i := 0; i <= 40; i++ {
// 		BingoShareHonestCase(i)
// 	}

// }

func TestBingoDeal(t *testing.T) {

	dealer := NewDealer()
	require.True(t, dealer.id == 0)

	//Create a Random number of secrets m
	m := 6

	secrets := make([]Secret, m)

	for i := 0; i < m; i++ {
		secrets[i] = *NewSecret(i, dealer.ReturnSuite())
	}

	d_1 := 10
	d_2 := 5
	n := 8

	setup, _ := kzg.NewKzgSetup(d_1+1, dealer.suite.suite)

	dealer.BingoDeal(secrets, d_1, d_2, n, setup)
	require.True(t, len(dealer.sharePolys) == n+1)
}

func TestKZG(t *testing.T) {

	dealer := NewDealer()
	require.True(t, dealer.id == 0)

	//Create a Random number of secrets m
	m := 7

	secrets := make([]Secret, m)

	for i := 0; i < m; i++ {
		secrets[i] = *NewSecret(i, dealer.ReturnSuite())
	}

	d_1 := 10
	d_2 := 5
	n := 8

	vn := make([]kyber.Scalar, n+1)
	for i := 0; i < n+1; i++ {
		vn[i] = dealer.ReturnSuite().suite.G1().Scalar().SetInt64(int64(i))
	}

	trap, _ := kzg.NewKzgSetup(d_1+1, dealer.suite.suite)
	sh_setup := kzg.NewShareSetup(trap.ReturnT_1(), trap.ReturnT_2(), trap.ReturnT_u(), dealer.suite.suite, trap.ReturnG_u(), trap.ReturnG_1(), trap.ReturnVal())

	CM, coem, verifiers := BingoShareDealer(secrets, d_1, d_2, n, 0, dealer.ReturnSuite(), trap)
	cm := kzg.PartialEval(trap, CM, coem, vn)

	//Step_5 : evaluate the polynomial at a specific point (for example I would evaluate it here at a=2)
	a := dealer.ReturnSuite().suite.G1().Scalar().SetInt64(0)

	// Step_6 : create an evaluation proof
	proof, y_1, y_2, _, _ := kzg.KZGEvaluationProof(trap, verifiers[0].polynomial.Coefficients(), verifiers[0].polynomial.Coefficients_2(), a)

	// //Step_7: verify the proof
	v := kzg.KZGVerify(sh_setup, cm, 0, proof, dealer.suite.suite.G1().Scalar().SetInt64(0), y_1, y_2) //this should return false

	require.True(t, v)
}

func BingoShareNotHonestCase(f int) {

	g := NewSuite()

	m := f + 1
	secrets := make([]Secret, m+1)
	for i := 0; i < m+1; i++ {
		secrets[i] = *NewSecret(i, *g)
	}

	d_1 := 2*f + 1
	d_2 := f
	n := 3*f + 1

	vn := make([]kyber.Scalar, n+1)
	for i := 0; i < n+1; i++ {
		vn[i] = g.suite.G1().Scalar().SetInt64(int64(i))
	}

	setup, _ := kzg.NewKzgSetup(d_1+1, g.suite)
	sh_setup := kzg.NewShareSetup(setup.ReturnT_1(), setup.ReturnT_2(), setup.ReturnT_u(), g.suite, setup.ReturnG_u(), setup.ReturnG_1(), setup.ReturnVal())

	verifiers := make([]Verifier, n+1)

	cm := make([]kyber.Point, n)

	for i := 0; i <= n+1; i++ {
		if i == 0 {
			CM, coem, ver := BingoShareDealer(secrets, d_1, d_2, n, 0, *g, setup)
			verifiers = ver
			cm = kzg.PartialEval(setup, CM, coem, vn)
		} else {
			if i < 2*f+1 {
				verifiers[i-1].UpdateStatus("not correct polynomials")
			}

			BingoShare(verifiers, d_1, d_2, n, i-1, cm, *g, sh_setup, setup)
			verifiers[i-1].UpdateStatus("has sent rows")
		}
	}

	for i := 0; i <= n; i++ {
		BingoShare(verifiers, d_1, d_2, n, i, cm, *g, sh_setup, setup)
		verifiers[i].UpdateStatus("Done")
		if i <= 2*f+1 {
			verifiers[i].UpdateStatus("missing polynomial")
		}

	}

	for i := 0; i <= n; i++ {
		BingoShare(verifiers, d_1, d_2, n, i, cm, *g, sh_setup, setup)
	}

	for i := 0; i < len(secrets); i++ {
		BingoReconstruct(verifiers, 0, sh_setup, i, d_2, cm)
		// require.True(t, secrets[i].s.Equal(secret))

	}

}

func BenchmarkHonestCasePerformance(b *testing.B) {
	for j := 2; j <= 42; j += 2 {
		b.Run(fmt.Sprintf("input_size_%d", j), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < 20; i++ {
				BingoShareHonestCase(1)
			}
		})
	}
}

func BenchmarkNotHonestCasePerformance(b *testing.B) {
	for j := 0; j <= 42; j += 2 {
		b.Run(fmt.Sprintf("input_size_%d", j), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < 20; i++ {
				BingoShareNotHonestCase(1)
			}

		})
	}
}

func BenchmarkNotHonestCaseTime(b *testing.B) {
	for j := 0; j <= 50; j += 1 {
		// for i := 8; i <= 64; i += 8 {
		b.Run(fmt.Sprintf("input_size_%d", 8), func(b *testing.B) {
			b.ResetTimer()
			BingoShareNotHonestCase(1)
		})
		// }

	}
}

func BenchmarkHonestCaseTime(b *testing.B) {
	for j := 0; j <= 50; j += 1 {
		// for i := 8; i <= 64; i += 8 {
		b.Run(fmt.Sprintf("input_size_%d", j), func(b *testing.B) {
			b.ResetTimer()
			BingoShareHonestCase(1)
		})
		// }

	}
}

func BingoShareHonestCase(f int) {
	g := NewSuite()

	//Create a Random number of secrets m
	m := f + 1
	secrets := make([]Secret, m+1)
	for i := 0; i < m+1; i++ {
		secrets[i] = *NewSecret(i, *g)
	}

	d_1 := 2*f + 1
	d_2 := f
	n := 3*f + 1

	vn := make([]kyber.Scalar, n+1)
	for i := 0; i < n+1; i++ {
		vn[i] = g.suite.G1().Scalar().SetInt64(int64(i))
	}

	setup, _ := kzg.NewKzgSetup(d_1+1, g.suite)
	sh_setup := kzg.NewShareSetup(setup.ReturnT_1(), setup.ReturnT_2(), setup.ReturnT_u(), g.suite, setup.ReturnG_u(), setup.ReturnG_1(), setup.ReturnVal())

	verifiers := make([]Verifier, n+1)

	cm := make([]kyber.Point, n)

	for i := 0; i <= n+1; i++ {
		if i == 0 {

			bingo, _ := os.OpenFile("test_BingoShare64.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			start := time.Now()

			CM, coem, ver := BingoShareDealer(secrets, d_1, d_2, n, 0, *g, setup)
			verifiers = ver
			cm = kzg.PartialEval(setup, CM, coem, vn)
			elapsed := time.Since(start)
			_, _ = bingo.WriteString(fmt.Sprintf("BingoShare of %d took %v to execute\n", f, elapsed))

		} else {
			BingoShare(verifiers, d_1, d_2, n, i-1, cm, *g, sh_setup, setup)
			verifiers[i-1].UpdateStatus("has sent rows")
		}
	}

	for i := 0; i <= n; i++ {
		BingoShare(verifiers, d_1, d_2, n, i, cm, *g, sh_setup, setup)
		verifiers[i].UpdateStatus("has sent columns")

	}

	//now is reconstruct time

	commit, _ := os.OpenFile("test_reconstruction64.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	start := time.Now()
	for i := 0; i < len(secrets); i++ {
		elapsed := time.Since(start)
		_, _ = commit.WriteString(fmt.Sprintf("Reconstruct of %d took %v to execute\n", f, elapsed))

	}
}

func TestBingoShareNotHonestCase(t *testing.T) {

	g := NewSuite()
	f := 2
	m := f + 1
	secrets := make([]Secret, m+1)
	for i := 0; i < m+1; i++ {
		secrets[i] = *NewSecret(i, *g)
	}

	d_1 := 2*f + 1
	d_2 := f
	n := 3*f + 1

	vn := make([]kyber.Scalar, n+1)
	for i := 0; i < n+1; i++ {
		vn[i] = g.suite.G1().Scalar().SetInt64(int64(i))
	}

	setup, _ := kzg.NewKzgSetup(d_1+1, g.suite)
	sh_setup := kzg.NewShareSetup(setup.ReturnT_1(), setup.ReturnT_2(), setup.ReturnT_u(), g.suite, setup.ReturnG_u(), setup.ReturnG_1(), setup.ReturnVal())

	verifiers := make([]Verifier, n+1)

	cm := make([]kyber.Point, n)

	for i := 0; i <= n+1; i++ {
		if i == 0 {
			CM, coem, ver := BingoShareDealer(secrets, d_1, d_2, n, 0, *g, setup)
			verifiers = ver
			cm = kzg.PartialEval(setup, CM, coem, vn)
		} else {
			if i < 2*f+1 {
				verifiers[i-1].UpdateStatus("not correct polynomials")
			}

			BingoShare(verifiers, d_1, d_2, n, i-1, cm, *g, sh_setup, setup)
			verifiers[i-1].UpdateStatus("has sent rows")
		}
	}

	for i := 0; i <= n; i++ {
		BingoShare(verifiers, d_1, d_2, n, i, cm, *g, sh_setup, setup)
		verifiers[i].UpdateStatus("Done")
		if i <= 2*f+1 {
			verifiers[i].UpdateStatus("missing polynomial")
		}

	}

	for i := 0; i <= n; i++ {
		BingoShare(verifiers, d_1, d_2, n, i, cm, *g, sh_setup, setup)
	}

	for i := 0; i < len(secrets); i++ {
		BingoReconstruct(verifiers, 0, sh_setup, i, d_2, cm)
		// require.True(t, secrets[i].s.Equal(secret))

	}

}

func TestBingoShareHonestCase(t *testing.T) {
	g := NewSuite()

	f := 2

	//Create a Random number of secrets m
	m := f + 1
	secrets := make([]Secret, m+1)
	for i := 0; i < m+1; i++ {
		secrets[i] = *NewSecret(i, *g)
	}

	d_1 := 2*f + 1
	d_2 := f
	n := 3*f + 1

	vn := make([]kyber.Scalar, n+1)
	for i := 0; i < n+1; i++ {
		vn[i] = g.suite.G1().Scalar().SetInt64(int64(i))
	}

	setup, _ := kzg.NewKzgSetup(d_1+1, g.suite)
	sh_setup := kzg.NewShareSetup(setup.ReturnT_1(), setup.ReturnT_2(), setup.ReturnT_u(), g.suite, setup.ReturnG_u(), setup.ReturnG_1(), setup.ReturnVal())

	verifiers := make([]Verifier, n+1)

	cm := make([]kyber.Point, n)

	for i := 0; i <= n+1; i++ {
		if i == 0 {

			CM, coem, ver := BingoShareDealer(secrets, d_1, d_2, n, 0, *g, setup)
			verifiers = ver
			cm = kzg.PartialEval(setup, CM, coem, vn)

		} else {
			BingoShare(verifiers, d_1, d_2, n, i-1, cm, *g, sh_setup, setup)
			verifiers[i-1].UpdateStatus("has sent rows")
		}
	}

	for i := 0; i <= n; i++ {
		BingoShare(verifiers, d_1, d_2, n, i, cm, *g, sh_setup, setup)
		verifiers[i].UpdateStatus("has sent columns")

	}

	//now is reconstruct time

	for i := 0; i < len(secrets); i++ {
		BingoReconstruct(verifiers, 0, sh_setup, i, d_2, cm)
	}

}
