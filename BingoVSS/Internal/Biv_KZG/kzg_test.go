package biv_kzg

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/stretchr/testify/require"
)

func TestPartialEval(t *testing.T) {

	// Initialize the pairing suite for cryptographic operations
	pairing := bn256.NewSuite()

	// Define the degrees of the polynomial in X and Y
	d_1 := 4 // Degree in X
	d_2 := 2 // Degree in Y

	trap, _ := NewKzgSetup(d_1+1, pairing) //this should eventually return an srs
	sh_setup := NewShareSetup(trap.ReturnT_1(), trap.ReturnT_2(), trap.ReturnT_u(), pairing, trap.ReturnG_u(), trap.ReturnG_1(), trap.ReturnVal())

	f_1 := make([][]kyber.Scalar, d_1+1) //this represents the Φ(Χ)
	f_2 := make([][]kyber.Scalar, d_1+1) //this represents the Φ'(Χ)

	for i := 0; i <= d_1; i++ {
		f_1[i] = make([]kyber.Scalar, d_2+1)
		f_2[i] = make([]kyber.Scalar, d_2+1)
		for j := 0; j <= d_2; j++ {
			f_1[i][j] = pairing.G1().Scalar().Pick(pairing.RandomStream())
			f_2[i][j] = pairing.G1().Scalar().Pick(pairing.RandomStream())
		}
	}

	//negative part

	x := []kyber.Scalar{
		pairing.G1().Scalar().Neg(pairing.G1().Scalar().SetInt64(0)),
		pairing.G1().Scalar().Neg(pairing.G1().Scalar().SetInt64(1)),
		pairing.G1().Scalar().Neg(pairing.G1().Scalar().SetInt64(2)),
		pairing.G1().Scalar().Neg(pairing.G1().Scalar().SetInt64(3)),
		pairing.G1().Scalar().Neg(pairing.G1().Scalar().SetInt64(4)),
	}
	y := []kyber.Scalar{
		pairing.G1().Scalar().SetInt64(2),
		pairing.G1().Scalar().SetInt64(1),
		pairing.G1().Scalar().SetInt64(10),
		pairing.G1().Scalar().SetInt64(59),
		pairing.G1().Scalar().SetInt64(202),
	}

	// Degree of the polynomial to interpolate
	degree := len(x) - 1

	// Generate Vandermonde matrix
	vMatrix := vandermonde(x, degree)

	// Solve the system of linear equations
	coeffs := solveLinearSystem(vMatrix, y)

	f_1 = adjustBivariateCoefficients(f_1, d_2+1, coeffs, pairing)

	a_f1_x := createProjectionPolynomials(pairing, f_1, d_1+1, d_2+1, d_2+1)

	f_final := interpolatePolynomial(f_1, a_f1_x, d_1+1, d_2+1)

	f_p := createProjectionPolynomials(pairing, f_final, d_1+1, d_2+1, d_2+1)

	f_p_2 := createProjectionPolynomials(pairing, f_2, d_1+1, d_2+1, d_2+1)

	CM, co := Commits(trap, f_final, f_2, d_1+1, d_2+1)

	vn := make([]kyber.Scalar, d_2+1)
	vn[0] = pairing.G1().Scalar().SetInt64(0)
	vn[1] = pairing.G1().Scalar().SetInt64(1)
	vn[2] = pairing.G1().Scalar().SetInt64(2)

	//first part done
	cm := PartialEval(trap, CM, co, vn)

	s := KZGCommits(sh_setup, f_p[2], f_p_2[2])

	require.True(t, cm[2].Equal(s))
	require.False(t, cm[2].Equal(CM[2]))

}

func TestSimple(t *testing.T) {

	//Step_0 : set the suite
	pairing := bn256.NewSuite()

	d_1 := 4 //the degree in x
	d_2 := 2 //the degree in y

	//Step_1 : we are going to have two polynomials okay, so the first step is to create the polynomials (3 degree polynomial)
	f_1 := make([][]kyber.Scalar, d_1+1) //this represents the Φ(Χ)
	f_1[0] = make([]kyber.Scalar, d_2+1)
	f_1[1] = make([]kyber.Scalar, d_2+1)
	f_1[2] = make([]kyber.Scalar, d_2+1)
	f_1[3] = make([]kyber.Scalar, d_2+1)
	f_1[4] = make([]kyber.Scalar, d_2+1)

	f_1[0][0] = pairing.G1().Scalar().SetInt64(6)
	f_1[0][1] = pairing.G1().Scalar().SetInt64(2)
	f_1[0][2] = pairing.G1().Scalar().SetInt64(2)
	f_1[1][0] = pairing.G1().Scalar().SetInt64(5)
	f_1[1][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[1][2] = pairing.G1().Scalar().SetInt64(1)
	f_1[2][0] = pairing.G1().Scalar().SetInt64(4)
	f_1[2][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[2][2] = pairing.G1().Scalar().SetInt64(1)
	f_1[3][0] = pairing.G1().Scalar().SetInt64(5)
	f_1[3][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[3][2] = pairing.G1().Scalar().SetInt64(1)
	f_1[4][0] = pairing.G1().Scalar().SetInt64(5)
	f_1[4][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[4][2] = pairing.G1().Scalar().SetInt64(1)

	//Step_1 : we are going to have two polynomials okay, so the first step is to create the polynomials (3 degree polynomial)
	f_2 := make([][]kyber.Scalar, d_1+1) //this represents the Φ(Χ)
	f_2[0] = make([]kyber.Scalar, d_2+1)
	f_2[1] = make([]kyber.Scalar, d_2+1)
	f_2[2] = make([]kyber.Scalar, d_2+1)
	f_2[3] = make([]kyber.Scalar, d_2+1)
	f_2[4] = make([]kyber.Scalar, d_2+1)

	f_2[0][0] = pairing.G1().Scalar().SetInt64(6)
	f_2[0][1] = pairing.G1().Scalar().SetInt64(2)
	f_2[0][2] = pairing.G1().Scalar().SetInt64(2)
	f_2[1][0] = pairing.G1().Scalar().SetInt64(5)
	f_2[1][1] = pairing.G1().Scalar().SetInt64(1)
	f_2[1][2] = pairing.G1().Scalar().SetInt64(1)
	f_2[2][0] = pairing.G1().Scalar().SetInt64(4)
	f_2[2][1] = pairing.G1().Scalar().SetInt64(1)
	f_2[2][2] = pairing.G1().Scalar().SetInt64(1)
	f_2[3][0] = pairing.G1().Scalar().SetInt64(5)
	f_2[3][1] = pairing.G1().Scalar().SetInt64(1)
	f_2[3][2] = pairing.G1().Scalar().SetInt64(1)
	f_2[4][0] = pairing.G1().Scalar().SetInt64(5)
	f_2[4][1] = pairing.G1().Scalar().SetInt64(1)
	f_2[4][2] = pairing.G1().Scalar().SetInt64(1)

	//Step_3: call the trusted setup, to setup the bilinear pairings in this setup we have an srs return
	// I am considering that the polynomials are from the same degree
	trap, err := NewKzgSetup(d_1+1, pairing) //this should eventually return an srs
	sh_setup := NewShareSetup(trap.ReturnT_1(), trap.ReturnT_2(), trap.ReturnT_u(), pairing, trap.ReturnG_u(), trap.ReturnG_1(), trap.ReturnVal())

	if err != nil {
		fmt.Println(trap)
	}

	//Step_4 : Use the setup (trusted setup) to commit the polynomial φ(x)
	com, co := Commits(trap, f_1, f_2, d_1+1, d_2+1)

	vn := make([]kyber.Scalar, d_2+1)
	vn[0] = pairing.G1().Scalar().SetInt64(1)
	vn[1] = pairing.G1().Scalar().SetInt64(2)
	vn[2] = pairing.G1().Scalar().SetInt64(3)

	f_1_x := createProjectionPolynomials(trap.g, f_1, d_1+1, d_2+1, d_2+1)

	f_2_x := createProjectionPolynomials(trap.g, f_2, d_1+1, d_2+1, d_2+1)

	alpha := PartialEval(trap, com, co, vn)

	//Step_5 : evaluate the polynomial at a specific point (for example I would evaluate it here at a=2)
	a := pairing.G1().Scalar().SetInt64(2)

	// Step_6 : create an evaluation proof
	proof, y_1, y_2, _, _ := KZGEvaluationProof(trap, f_1_x[1], f_2_x[1], a)

	// //Step_7: verify the proof
	v := KZGVerify(sh_setup, alpha, 1, proof, pairing.G1().Scalar().SetInt64(2), y_1, y_2) //this should return false

	require.True(t, v)

	v = KZGVerify(sh_setup, com, 1, proof, a, y_1, y_2) //this should return false

	require.False(t, v)

}

// func TestRandomMultiple(t *testing.T) {
// 	file, err := os.Create("test_results.txt")
// 	if err != nil {
// 		t.Fatalf("Failed to create results file: %v", err)
// 	}
// 	defer file.Close()

// 	for i := 2; i <= 130; i += 2 {
// 		start := time.Now()
// 		Random(i)
// 		elapsed := time.Since(start)

// 		result := fmt.Sprintf("Run %d with f = %d took %v to execute\n", i, i, elapsed)
// 		file.WriteString(result)
// 	}
// }

// func Random(f int) {
// 	//Step_0 : set the suite
// 	pairing := bn256.NewSuite()

// 	d_1 := 2 * f //the degree in x
// 	d_2 := f     //the degree in y

// 	//Step_1 : we are going to have two polynomials okay, so the first step is to create the polynomials (3 degree polynomial)
// 	f_1 := make([][]kyber.Scalar, d_1+1) //this represents the Φ(Χ)
// 	f_2 := make([][]kyber.Scalar, d_1+1) //this represents the Φ(Χ)

// 	for i := 0; i < d_1+1; i++ {
// 		f_1[i] = make([]kyber.Scalar, d_2+1)
// 		f_2[i] = make([]kyber.Scalar, d_2+1)
// 		for j := 0; j < d_2+1; j++ {
// 			f_1[i][j] = pairing.G1().Scalar().Pick(pairing.RandomStream())
// 			f_2[i][j] = pairing.G1().Scalar().Pick(pairing.RandomStream())
// 		}
// 	}
// 	setup, err := os.OpenFile("test_setup.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	start := time.Now()
// 	trap, err := NewKzgSetup(d_1, pairing) //this should eventually return an srs
// 	sh_setup := NewShareSetup(trap.ReturnT_1(), trap.ReturnT_2(), trap.ReturnT_u(), pairing, trap.ReturnG_u(), trap.ReturnG_1(), trap.ReturnVal())
// 	elapsed := time.Since(start)
// 	setup.WriteString(fmt.Sprintf("Setup took %v to execute\n", elapsed))

// 	if err != nil {
// 		fmt.Println(trap)
// 	}

// 	commit, err := os.OpenFile("test_commit.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	//Step_4 : Use the setup (trusted setup) to commit the polynomial φ(x)
// 	start = time.Now()
// 	com, co := Commits(trap, f_1, f_2, d_1, d_2)
// 	elapsed = time.Since(start)

// 	commit.WriteString(fmt.Sprintf("Commit took %v to execute\n", elapsed))

// 	vn := make([]kyber.Scalar, d_2+1)
// 	for i := 0; i < d_2+1; i++ {
// 		vn[i] = pairing.G1().Scalar().Pick(pairing.RandomStream())

// 	}

// 	f_1_x := createProjectionPolynomials(trap.g, f_1, d_1+1, d_2+1, d_2+1)
// 	f_2_x := createProjectionPolynomials(trap.g, f_2, d_1+1, d_2+1, d_2+1)

// 	partial, err := os.OpenFile("test_partial.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	//Step_4 : Use the setup (trusted setup) to commit the polynomial φ(x)
// 	start = time.Now()
// 	cm := PartialEval(trap, com, co, vn)
// 	elapsed = time.Since(start)

// 	partial.WriteString(fmt.Sprintf("Partial took %v to execute\n", elapsed))

// 	//Step_5 : evaluate the polynomial at a specific point (for example I would evaluate it here at a=2)
// 	a := pairing.G1().Scalar().SetInt64(2)

// 	y_1 := evaluatePolynomial(f_1_x[1], a, pairing)
// 	y_2 := evaluatePolynomial(f_2_x[1], a, pairing)

// 	if debug == 1 {
// 		yBytes, _ := y_1.MarshalBinary()
// 		yBigInt := new(big.Int).SetBytes(yBytes)
// 		fmt.Println("  to = ", yBigInt)

// 		yBytes, _ = y_2.MarshalBinary()
// 		yBigInt = new(big.Int).SetBytes(yBytes)
// 		fmt.Println("  to = ", yBigInt)
// 		if yBigInt == new(big.Int).SetInt64(16) {
// 			fmt.Println("correct")
// 		}
// 	}

// 	proof_t, err := os.OpenFile("test_proof.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	start = time.Now()
// 	// Step_6 : create an evaluation proof
// 	proof, _, _, _, _ := KZGEvaluationProof(trap, f_1_x[1], f_2_x[1], a)
// 	elapsed = time.Since(start)

// 	proof_t.WriteString(fmt.Sprintf("Proof took %v to execute\n", elapsed))

// 	verify, err := os.OpenFile("test_verify.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	start = time.Now()
// 	KZGVerify(sh_setup, cm, 1, proof, a, y_1, y_2) //this should return false
// 	elapsed = time.Since(start)
// 	verify.WriteString(fmt.Sprintf("Verify took %v to execute\n", elapsed))

// }

func TestRandom(t *testing.T) {
	//Step_0 : set the suite
	pairing := bn256.NewSuite()

	f := 2

	d_1 := 2 * f //the degree in x
	d_2 := f     //the degree in y

	//Step_1 : we are going to have two polynomials okay, so the first step is to create the polynomials (3 degree polynomial)
	f_1 := make([][]kyber.Scalar, d_1+1) //this represents the Φ(Χ)
	f_2 := make([][]kyber.Scalar, d_1+1) //this represents the Φ(Χ)

	for i := 0; i < d_1+1; i++ {
		f_1[i] = make([]kyber.Scalar, d_2+1)
		f_2[i] = make([]kyber.Scalar, d_2+1)
		for j := 0; j < d_2+1; j++ {
			f_1[i][j] = pairing.G1().Scalar().Pick(pairing.RandomStream())
			f_2[i][j] = pairing.G1().Scalar().Pick(pairing.RandomStream())
		}
	}

	trap, err := NewKzgSetup(d_1, pairing) //this should eventually return an srs
	sh_setup := NewShareSetup(trap.ReturnT_1(), trap.ReturnT_2(), trap.ReturnT_u(), pairing, trap.ReturnG_u(), trap.ReturnG_1(), trap.ReturnVal())

	if err != nil {
		fmt.Println(trap)
	}

	//Step_4 : Use the setup (trusted setup) to commit the polynomial φ(x)

	com, co := Commits(trap, f_1, f_2, d_1, d_2)

	vn := make([]kyber.Scalar, d_2+1)
	for i := 0; i < d_2+1; i++ {
		vn[i] = pairing.G1().Scalar().Pick(pairing.RandomStream())

	}

	f_1_x := createProjectionPolynomials(trap.g, f_1, d_1+1, d_2+1, d_2+1)
	f_2_x := createProjectionPolynomials(trap.g, f_2, d_1+1, d_2+1, d_2+1)

	//Step_4 : Use the setup (trusted setup) to commit the polynomial φ(x)

	cm := PartialEval(trap, com, co, vn)

	//Step_5 : evaluate the polynomial at a specific point (for example I would evaluate it here at a=2)
	a := pairing.G1().Scalar().SetInt64(2)

	y_1 := evaluatePolynomial(f_1_x[1], a, pairing)
	y_2 := evaluatePolynomial(f_2_x[1], a, pairing)

	if debug == 1 {
		yBytes, _ := y_1.MarshalBinary()
		yBigInt := new(big.Int).SetBytes(yBytes)
		fmt.Println("  to = ", yBigInt)

		yBytes, _ = y_2.MarshalBinary()
		yBigInt = new(big.Int).SetBytes(yBytes)
		fmt.Println("  to = ", yBigInt)
		if yBigInt == new(big.Int).SetInt64(16) {
			fmt.Println("correct")
		}
	}

	// Step_6 : create an evaluation proof
	proof, _, _, _, _ := KZGEvaluationProof(trap, f_1_x[1], f_2_x[1], a)

	KZGVerify(sh_setup, cm, 1, proof, a, y_1, y_2) //this should return false

}
