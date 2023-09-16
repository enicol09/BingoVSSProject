package interpolation

import (
	"fmt"
	"sort"
	"testing"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/mat"
)

func TestSimpleVandermonde(t *testing.T) {

	// Initialize the pairing suite for cryptographic operations
	pairing := bn256.NewSuite()

	// Define the degrees of the polynomial in X and Y
	d_1 := 4 // Degree in X
	d_2 := 2 // Degree in Y

	// Initialize the bivariate polynomial f_1 to represent Φ(X)
	f_1 := make([][]kyber.Scalar, d_1)
	for i := range f_1 {
		f_1[i] = make([]kyber.Scalar, d_2)
	}

	// Set the coefficients of the polynomial f_1
	f_1[0][0] = pairing.G1().Scalar().SetInt64(6) // coedf a0
	f_1[0][1] = pairing.G1().Scalar().SetInt64(2)
	f_1[1][0] = pairing.G1().Scalar().SetInt64(5) // coef a1
	f_1[1][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[2][0] = pairing.G1().Scalar().SetInt64(4) // coef a2
	f_1[2][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[3][0] = pairing.G1().Scalar().SetInt64(5) // coef 3
	f_1[3][1] = pairing.G1().Scalar().SetInt64(1)

	// Define the secret values
	s_0 := pairing.G1().Scalar().SetInt64(4)
	s_1 := pairing.G1().Scalar().SetInt64(2)

	// Convert the secret values to float for matrix operations
	s_0_f := convert_to_float(s_0)
	s_1_f := convert_to_float(s_1)

	// Define the x-values and corresponding y-values for interpolation
	xValues := []float64{0, -1} // s0 corresponds to x=0, s1 corresponds to x=-1
	yValues := []float64{s_0_f, s_1_f}

	// Create the Vandermonde matrix using the x-values and degree in X
	V := createVandermonde(xValues, d_1) //phi(X,0) = f(x) = a0x^0

	// Solve for the coefficients of the polynomial using the Vandermonde matrix and y-values
	b := mat.NewDense(len(yValues), 1, yValues)
	var coefs mat.Dense
	err := coefs.Solve(V, b)
	if err != nil {
		fmt.Println(err)
	}

	// Print the obtained coefficients
	co := coefs.RawMatrix().Data
	fmt.Println("Coefficients:", co)

}

func TestReconstructionRandom(t *testing.T) {

	// Initialize the pairing suite for cryptographic operations
	pairing := bn256.NewSuite()

	// Define the degrees of the polynomial in X and Y
	d_1 := 4 // Degree in X
	d_2 := 2 // Degree in Y

	f_1 := make([][]kyber.Scalar, d_1+1)

	for i := 0; i <= d_1; i++ {
		f_1[i] = make([]kyber.Scalar, d_2+1)
		for j := 0; j <= d_2; j++ {
			f_1[i][j] = pairing.G1().Scalar().Pick(pairing.RandomStream())
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
		pairing.G1().Scalar().Pick(pairing.RandomStream()),
		pairing.G1().Scalar().Pick(pairing.RandomStream()),
		pairing.G1().Scalar().Pick(pairing.RandomStream()),
		pairing.G1().Scalar().Pick(pairing.RandomStream()),
		pairing.G1().Scalar().Pick(pairing.RandomStream()),
	}

	s := y[4]

	// Degree of the polynomial to interpolate
	degree := len(x) - 1

	// Generate Vandermonde matrix
	vMatrix := vandermonde(x, degree)

	// Solve the system of linear equations
	coeffs := solveLinearSystem(vMatrix, y)

	f_1 = adjustBivariateCoefficients(f_1, d_2+1, coeffs, pairing)

	a_f1_x := createProjectionPolynomials(pairing, f_1, d_1+1, d_2+1, d_2+1)

	//polynomialPrint(a_f1_x, d_1+1, d_2+1)

	f_final := interpolatePolynomial(f_1, a_f1_x, d_1+1, d_2+1)

	//polynomialPrintAll(f_final, d_1+1, d_2+1)

	f_p := createProjectionPolynomials(pairing, f_final, d_1+1, d_2+1, d_2+1)

	//polynomialPrint(f_p, d_1+1, d_2+1)

	xs := pairing.G1().Scalar().Neg(pairing.G1().Scalar().SetInt64(4))
	share_0 := evaluatePolynomial(f_p[0], xs, pairing)
	share_1 := evaluatePolynomial(f_p[1], xs, pairing)
	//share_2 := evaluatePolynomial(f_p[2], xs, pairing)

	x = []kyber.Scalar{
		pairing.G1().Scalar().SetInt64(0),
		pairing.G1().Scalar().SetInt64(1),
		//pairing.G1().Scalar().SetInt64(2),
	}
	y = []kyber.Scalar{
		share_0,
		share_1,
		//share_2,
	}

	// Degree of the polynomial to interpolate
	degree = len(x) - 1

	// Generate Vandermonde matrix
	vMatrix = vandermonde(x, degree)

	// Solve the system of linear equations
	coeffs = solveLinearSystem(vMatrix, y)

	xy := pairing.G1().Scalar().SetInt64(0)

	result := evaluatePolynomial(coeffs, xy, pairing)

	require.True(t, result.Equal(s))
}

func TestReconstruction(t *testing.T) {

	// Initialize the pairing suite for cryptographic operations
	pairing := bn256.NewSuite()

	// Define the degrees of the polynomial in X and Y
	d_1 := 4 // Degree in X
	d_2 := 2 // Degree in Y

	f_1 := make([][]kyber.Scalar, d_1+1) //this represents the Φ(Χ)
	f_1[0] = make([]kyber.Scalar, d_2+1)
	f_1[1] = make([]kyber.Scalar, d_2+1)
	f_1[2] = make([]kyber.Scalar, d_2+1)
	f_1[3] = make([]kyber.Scalar, d_2+1)
	f_1[4] = make([]kyber.Scalar, d_2+1)

	f_1[0][0] = pairing.G1().Scalar().SetInt64(2)
	//x^0y^0 = 0
	f_1[0][1] = pairing.G1().Scalar().SetInt64(2)
	//
	f_1[0][2] = pairing.G1().Scalar().SetInt64(2)

	f_1[1][0] = pairing.G1().Scalar().SetInt64(0)
	f_1[1][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[1][2] = pairing.G1().Scalar().SetInt64(1)

	f_1[2][0] = pairing.G1().Scalar().SetInt64(0)
	f_1[2][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[2][2] = pairing.G1().Scalar().SetInt64(1)

	f_1[3][0] = pairing.G1().Scalar().SetInt64(0)
	f_1[3][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[3][2] = pairing.G1().Scalar().SetInt64(1)

	f_1[4][0] = pairing.G1().Scalar().SetInt64(0)
	f_1[4][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[4][2] = pairing.G1().Scalar().SetInt64(1)

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

	//polynomialPrint(a_f1_x, d_1+1, d_2+1)

	f_final := interpolatePolynomial(f_1, a_f1_x, d_1+1, d_2+1)

	//polynomialPrintAll(f_final, d_1+1, d_2+1)

	f_p := createProjectionPolynomials(pairing, f_final, d_1+1, d_2+1, d_2+1)

	//polynomialPrint(f_p, d_1+1, d_2+1)

	xs := pairing.G1().Scalar().Neg(pairing.G1().Scalar().SetInt64(3))
	share_0 := evaluatePolynomial(f_p[0], xs, pairing)
	share_1 := evaluatePolynomial(f_p[1], xs, pairing)
	//share_2 := evaluatePolynomial(f_p[2], xs, pairing)

	x = []kyber.Scalar{
		pairing.G1().Scalar().SetInt64(0),
		pairing.G1().Scalar().SetInt64(1),
		//pairing.G1().Scalar().SetInt64(2),
	}
	y = []kyber.Scalar{
		share_0,
		share_1,
		//share_2,
	}

	// Degree of the polynomial to interpolate
	degree = len(x) - 1

	// Generate Vandermonde matrix
	vMatrix = vandermonde(x, degree)

	// Solve the system of linear equations
	coeffs = solveLinearSystem(vMatrix, y)

	xy := pairing.G1().Scalar().SetInt64(0)

	result := evaluatePolynomial(coeffs, xy, pairing)

	require.True(t, result.Equal(pairing.G1().Scalar().SetInt64(59)))
}

func TestVandermondeScalar(t *testing.T) {
	suite := bn256.NewSuite()

	// Data points
	x := []kyber.Scalar{
		suite.G1().Scalar().SetInt64(1),
		suite.G1().Scalar().SetInt64(2),
		suite.G1().Scalar().SetInt64(3),
		suite.G1().Scalar().SetInt64(4),
		suite.G1().Scalar().SetInt64(5),
	}
	y := []kyber.Scalar{
		suite.G1().Scalar().SetInt64(2),
		suite.G1().Scalar().SetInt64(12),
		suite.G1().Scalar().SetInt64(104),
		suite.G1().Scalar().SetInt64(76),
		suite.G1().Scalar().SetInt64(18),
	}

	// Degree of the polynomial to interpolate
	degree := len(x) - 1

	// Generate Vandermonde matrix
	vMatrix := vandermonde(x, degree)

	// Solve the system of linear equations
	coeffs := solveLinearSystem(vMatrix, y)

	xy := suite.G1().Scalar().SetInt64(5)
	evaluatePolynomial(coeffs, xy, suite)

}

func TestVandermondeScalarRandom(t *testing.T) {
	suite := bn256.NewSuite()

	// Data points
	x := []kyber.Scalar{
		suite.G1().Scalar().Neg(suite.G1().Scalar().SetInt64(1)),
		suite.G1().Scalar().Neg(suite.G1().Scalar().SetInt64(2)),
		suite.G1().Scalar().Neg(suite.G1().Scalar().SetInt64(3)),
		suite.G1().Scalar().Neg(suite.G1().Scalar().SetInt64(4)),
		suite.G1().Scalar().Neg(suite.G1().Scalar().SetInt64(5)),
	}
	y := []kyber.Scalar{
		suite.G1().Scalar().Pick(suite.RandomStream()),
		suite.G1().Scalar().Pick(suite.RandomStream()),
		suite.G1().Scalar().Pick(suite.RandomStream()),
		suite.G1().Scalar().Pick(suite.RandomStream()),
		suite.G1().Scalar().Pick(suite.RandomStream()),
	}

	sort.Sort(ScalarSlice(y))

	// Degree of the polynomial to interpolate
	degree := len(x) - 1

	// Generate Vandermonde matrix
	vMatrix := vandermonde(x, degree)

	// Solve the system of linear equations
	coeffs := solveLinearSystem(vMatrix, y)

	d_1 := 4
	d_2 := 2

	f_1 := make([][]kyber.Scalar, d_1+1)
	for i := range f_1 {
		f_1[i] = make([]kyber.Scalar, d_2+1)
		for j := 0; j < d_2+1; j++ {
			f_1[i][j] = suite.G1().Scalar().Pick(suite.RandomStream())
		}
	}

	// Set the coefficients of the polynomial f_1
	adjustBivariateCoefficients(f_1, d_2, coeffs, suite)
}

func TestRandomVandermonde(t *testing.T) {

	// Initialize the pairing suite for cryptographic operations
	pairing := bn256.NewSuite()

	// Define the degrees of the polynomial in X and Y
	d_1 := 4 // Degree in X
	d_2 := 2 // Degree in Y

	// Initialize the bivariate polynomial f_1 to represent Φ(X)
	f_1 := make([][]kyber.Scalar, d_1)
	for i := range f_1 {
		f_1[i] = make([]kyber.Scalar, d_2)
	}

	// Set the coefficients of the polynomial f_1
	f_1[0][0] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_1[0][1] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_1[1][0] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_1[1][1] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_1[2][0] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_1[2][1] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_1[3][0] = pairing.G1().Scalar().Pick(pairing.RandomStream())
	f_1[3][1] = pairing.G1().Scalar().Pick(pairing.RandomStream())

	// Define the secret values
	s_0 := pairing.G1().Scalar().Pick(pairing.RandomStream())
	s_1 := pairing.G1().Scalar().Pick(pairing.RandomStream())

	// Convert the secret values to float for matrix operations
	s_0_f := convert_to_float(s_0)
	s_1_f := convert_to_float(s_1)

	// Define the x-values and corresponding y-values for interpolation
	xValues := []float64{0, -1} // s0 corresponds to x=0, s1 corresponds to x=-1
	yValues := []float64{s_0_f, s_1_f}

	// Create the Vandermonde matrix using the x-values and degree in X
	V := createVandermonde(xValues, d_1)

	// Solve for the coefficients of the polynomial using the Vandermonde matrix and y-values
	b := mat.NewDense(len(yValues), 1, yValues)
	var coefs mat.Dense
	err := coefs.Solve(V, b)

	if err != nil {
		fmt.Println(err)
	}

}

func TestSimpleLangrange(t *testing.T) {

	// Initialize the pairing suite for cryptographic operations
	pairing := bn256.NewSuite()

	// Define the degrees of the polynomial in X and Y
	d_1 := 4 // Degree in X
	d_2 := 2 // Degree in Y

	// Initialize the bivariate polynomial f_1 to represent Φ(X)
	f_1 := make([][]kyber.Scalar, d_1)
	for i := range f_1 {
		f_1[i] = make([]kyber.Scalar, d_2)
	}

	// Set the coefficients of the polynomial f_1
	f_1[0][0] = pairing.G1().Scalar().SetInt64(6)
	f_1[0][1] = pairing.G1().Scalar().SetInt64(2)
	f_1[1][0] = pairing.G1().Scalar().SetInt64(5)
	f_1[1][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[2][0] = pairing.G1().Scalar().SetInt64(4)
	f_1[2][1] = pairing.G1().Scalar().SetInt64(1)
	f_1[3][0] = pairing.G1().Scalar().SetInt64(5)
	f_1[3][1] = pairing.G1().Scalar().SetInt64(1)

	// Define the secret values
	s_0 := pairing.G1().Scalar().SetInt64(5)
	s_1 := pairing.G1().Scalar().SetInt64(4)

	// Convert the secret values to float for matrix operations
	s_0_f := convert_to_float(s_0)
	s_1_f := convert_to_float(s_1)

	// Define the x-values and corresponding y-values for interpolation
	xValues := []float64{-2, 0} // s0 corresponds to x=0, s1 corresponds to x=-1
	yValues := []float64{s_0_f, s_1_f}

	x := 0.0
	y := LagrangeInterpolation(x, xValues, yValues)
	require.True(t, y == 4)
}
