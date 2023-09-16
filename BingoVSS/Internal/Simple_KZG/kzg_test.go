package kzg_simple

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/stretchr/testify/require"
)

func TestSimple(t *testing.T) {

	//Step_0 : set the suite
	pairing := bn256.NewSuite()

	//Step_1 : create a polynomial (4 degree polynomial)
	f := make([]kyber.Scalar, 4) //this represents the Φ(Χ)

	//Step_2 : set your own values to the polynomials as exampple now we have 	φ(x) = x^3 + x + 6
	f[0] = pairing.G1().Scalar().SetInt64(6)
	f[1] = pairing.G1().Scalar().SetInt64(1) // x^1
	f[2] = pairing.G1().Scalar().SetInt64(0) // x^2
	f[3] = pairing.G1().Scalar().SetInt64(1) // x^3

	//Step_3: call the trusted setup, to setup the bilinear pairings
	trap, err := NewKzgSetup(len(f), pairing)

	if err != nil {
		fmt.Println(trap)
	}

	//Step_4 : Use the setup (trusted setup) to commit the polynomial φ(x)
	com := KZGCommits(trap, f)

	//Step_5 : evaluate the polynomial at a specific point (for example I would evaluate it here at a=2)
	a := pairing.G1().Scalar().SetInt64(2)
	y := evaluatePolynomial(f, a, pairing)

	if debug == 1 {
		yBytes, _ := y.MarshalBinary()
		yBigInt := new(big.Int).SetBytes(yBytes)
		if yBigInt == new(big.Int).SetInt64(16) {
			fmt.Println("correct")
		}
	}

	// Step_6 : create an evaluation proof
	proof, _ := KZGEvaluationProof(trap, f, a, y)

	//Step_7: verify the proof
	v := KZGVerify(trap, com, proof, pairing.G1().Scalar().SetInt64(3), y) //this should return false

	require.False(t, v)

	v = KZGVerify(trap, com, proof, a, y) //this should return true

	require.True(t, v)

}

func TestRandom(t *testing.T) {

	//Step_0 : set the suite
	pairing := bn256.NewSuite()

	// //Step_1 : create a polynomial (4 degree polynomial)
	// f := make([]kyber.Scalar, 5) //this represents the Φ(Χ)

	//Step_2 : set random values to the polynomials as exampple now we have 	φ(x) = x^3 + x + 6
	f := []kyber.Scalar{
		pairing.G1().Scalar().Pick(pairing.RandomStream()),
		pairing.G1().Scalar().Pick(pairing.RandomStream()),
		pairing.G1().Scalar().Pick(pairing.RandomStream()),
		pairing.G1().Scalar().Pick(pairing.RandomStream()),
	}

	//Step_3: call the trusted setup, to setup the bilinear pairings
	trap, err := NewKzgSetup(len(f), pairing)

	if err != nil {
		fmt.Println(trap)
	}

	//Step_4 : Use the setup (trusted setup) to commit the polynomial φ(x)
	com := KZGCommits(trap, f)

	//Step_5 : evaluate the polynomial at a specific point (for example I would evaluate it here at a=2)
	a := pairing.G1().Scalar().SetInt64(2)
	y := evaluatePolynomial(f, a, pairing)

	if debug == 1 {
		yBytes, _ := y.MarshalBinary()
		yBigInt := new(big.Int).SetBytes(yBytes)
		if yBigInt == new(big.Int).SetInt64(16) {
			fmt.Println("correct")
		}
	}

	// Step_6 : create an evaluation proof
	proof, _ := KZGEvaluationProof(trap, f, a, y)

	//Step_7: verify the proof
	v := KZGVerify(trap, com, proof, pairing.G1().Scalar().SetInt64(3), y) //this should return false

	require.False(t, v)

	v = KZGVerify(trap, com, proof, a, y) //this should return true

	require.True(t, v)

}
