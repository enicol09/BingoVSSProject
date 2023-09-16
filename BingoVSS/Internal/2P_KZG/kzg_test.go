package polytwo_kzg

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

	//Step_1 : we are going to have two polynomials okay, so the first step is to create the polynomials (3 degree polynomial)
	f_1 := make([]kyber.Scalar, 4) //this represents the Φ(Χ)
	f_2 := make([]kyber.Scalar, 4)

	//Step_2 : set your own values to the polynomials as exampple now we have

	// f_1 = φ1(x) = x^3 + x + 6
	f_1[0] = pairing.G1().Scalar().SetInt64(6)
	f_1[1] = pairing.G1().Scalar().SetInt64(5) // x^1
	f_1[2] = pairing.G1().Scalar().SetInt64(4) // x^2
	f_1[3] = pairing.G1().Scalar().SetInt64(5) // x^3

	// f_1 = φ1(x) = x^3 + x + 4
	f_2[0] = pairing.G1().Scalar().SetInt64(6)
	f_2[1] = pairing.G1().Scalar().SetInt64(5) // x^1
	f_2[2] = pairing.G1().Scalar().SetInt64(4) // x^2
	f_2[3] = pairing.G1().Scalar().SetInt64(5) // x^3

	//Step_3: call the trusted setup, to setup the bilinear pairings in this setup we have an srs return
	// I am considering that the polynomials are from the same degree
	trap, err := NewKzgSetup(len(f_1), pairing) //this should eventually return an srs

	if err != nil {
		fmt.Println(trap)
	}

	//Step_4 : Use the setup (trusted setup) to commit the polynomial φ(x)
	com := KZGCommits(trap, f_1, f_2)

	//Step_5 : evaluate the polynomial at a specific point (for example I would evaluate it here at a=2)
	a := pairing.G1().Scalar().SetInt64(2)
	y_1 := evaluatePolynomial(f_1, a, pairing)
	y_2 := evaluatePolynomial(f_2, a, pairing)

	if debug == 1 {
		yBytes, _ := y_1.MarshalBinary()
		yBigInt := new(big.Int).SetBytes(yBytes)
		if yBigInt == new(big.Int).SetInt64(16) {
			fmt.Println("correct")
		}

		yBytes, _ = y_2.MarshalBinary()
		yBigInt = new(big.Int).SetBytes(yBytes)
		if yBigInt == new(big.Int).SetInt64(16) {
			fmt.Println("correct")
		}
	}

	// Step_6 : create an evaluation proof
	proof, _ := KZGEvaluationProof(trap, f_1, f_2, a, y_1, y_2)

	//Step_7: verify the proof
	v := KZGVerify(trap, com, proof, pairing.G1().Scalar().SetInt64(3), y_1, y_2) //this should return false

	require.False(t, v)

	v = KZGVerify(trap, com, proof, a, y_1, y_2) //this should return true

	require.True(t, v)

}

func TestRandom(t *testing.T) {
	//Step_0 : set the suite
	pairing := bn256.NewSuite()

	//Step_1 : we are going to have two polynomials okay, so the first step is to create the polynomials (3 degree polynomial)
	f_1 := make([]kyber.Scalar, 4) //this represents the Φ(Χ)
	f_2 := make([]kyber.Scalar, 4)

	//Step_2 : set your own values to the polynomials as exampple now we have

	// f_1 = φ1(x) = x^3 + x + 6
	f_1[0] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_1[1] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_1[2] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_1[3] = pairing.G1().Scalar().Pick(pairing.RandomStream())

	// f_1 = φ1(x) = x^3 + x + 4
	f_2[0] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_2[1] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_2[2] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_2[3] = pairing.G1().Scalar().Pick(pairing.RandomStream())

	//Step_3: call the trusted setup, to setup the bilinear pairings in this setup we have an srs return
	// I am considering that the polynomials are from the same degree
	trap, err := NewKzgSetup(len(f_1), pairing) //this should eventually return an srs

	if err != nil {
		fmt.Println(trap)
	}

	//Step_4 : Use the setup (trusted setup) to commit the polynomial φ(x)
	com := KZGCommits(trap, f_1, f_2)

	//Step_5 : evaluate the polynomial at a specific point (for example I would evaluate it here at a=2)
	a := pairing.G1().Scalar().SetInt64(2)
	y_1 := evaluatePolynomial(f_1, a, pairing)
	y_2 := evaluatePolynomial(f_2, a, pairing)

	// Step_6 : create an evaluation proof
	proof, _ := KZGEvaluationProof(trap, f_1, f_2, a, y_1, y_2)

	//Step_7: verify the proof
	v := KZGVerify(trap, com, proof, pairing.G1().Scalar().SetInt64(3), y_1, y_2) //this should return false

	require.False(t, v)

	v = KZGVerify(trap, com, proof, a, y_1, y_2) //this should return true
	require.True(t, v)

}
