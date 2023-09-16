package interpolation

import (
	"bytes"
	"math/big"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
)

// interpolatePolynomial takes in two 2D slices (f_1 and a_f1_x) and their dimensions (d_1 and d_2).
// It transposes the values of a_f1_x into f_1. The primary goal is a matrix transposition, based on the
// new given eleements
func interpolatePolynomial(f_1 [][]kyber.Scalar, a_f1_x [][]kyber.Scalar, d_1, d_2 int) [][]kyber.Scalar {

	// Loop through the rows of a_f1_x (which become columns in f_1).
	for i := 0; i < d_2; i++ {
		// Loop through the columns of a_f1_x (which become rows in f_1).
		for j := 0; j < d_1; j++ {
			// Transpose the element.
			f_1[j][i] = a_f1_x[i][j]
		}
	}

	// Return the transposed matrix.
	return f_1
}

// convert_to_float converts a kyber.Scalar to a float64.
// The process involves marshaling the scalar to bytes, then converting those bytes to big.Int,
// subsequently converting that big.Int to big.Float, and finally converting the big.Float to float64.
func convert_to_float(s_0 kyber.Scalar) float64 {
	// Marshal the scalar to bytes.
	s_0Bytes, _ := s_0.MarshalBinary()

	// Convert the bytes to big.Int.
	s_0BigInt := new(big.Int).SetBytes(s_0Bytes)

	// Convert the big.Int to big.Float.
	bigFloatValue := new(big.Float).SetInt(s_0BigInt)

	// Convert the big.Float to float64.
	float64Value, _ := bigFloatValue.Float64()

	// Return the float64 value.
	return float64Value
}

// adjustBivariateCoefficients updates the first column of a bivariate polynomial (that means
// the coefficients of the fist polynomial φ(Χ,0) with the given coefficients
// occured through interpolation
func adjustBivariateCoefficients(f_1 [][]kyber.Scalar, d_2 int, co []kyber.Scalar, group *bn256.Suite) [][]kyber.Scalar {

	for i := 0; i < len(co); i++ {
		f_1[i][0] = co[i]
	}

	return f_1
}

// EvaluatePolynomial evaluates a polynomial p at a given value x.
// It takes a slice of kyber.Scalar values representing the coefficients of the polynomial p,
// a kyber.Scalar value x representing the point at which to evaluate the polynomial,
// and a bn256.Suite object suite for performing arithmetic operations.
// It returns the result of the evaluation as a kyber.Scalar value.
func evaluatePolynomial(p []kyber.Scalar, x kyber.Scalar, suite *bn256.Suite) kyber.Scalar {
	// Initialize the result r to zero
	r := suite.G1().Scalar().Zero()

	// Initialize a temporary variable tmp to one, to be used for calculating the power of x
	tmp := suite.G1().Scalar().One()

	// Iterate through the coefficients of the polynomial p
	for _, coeff := range p {
		// Multiply the current coefficient by the current power of x (stored in tmp)
		term := suite.G1().Scalar().Mul(tmp, coeff)

		// Add the result to the current value of r
		r = suite.G1().Scalar().Add(r, term)

		// Multiply tmp by x, increasing the power of x for the next iteration
		tmp = suite.G1().Scalar().Mul(tmp, x)
	}

	// Return the result of the evaluation
	return r
}

type ScalarSlice []kyber.Scalar

func (s ScalarSlice) Len() int {
	return len(s)
}

func (s ScalarSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s ScalarSlice) Less(i, j int) bool {
	bytes1, _ := s[i].MarshalBinary()
	bytes2, _ := s[j].MarshalBinary()
	return bytes.Compare(bytes1, bytes2) < 0
}

func createProjectionPolynomials(g *bn256.Suite, f_x [][]kyber.Scalar, d_1 int, d_2 int, n int) [][]kyber.Scalar {

	// Create a 2D array to store the univariate polynomials
	uni_f := make([][]kyber.Scalar, n)

	// Extract the univariate polynomials
	for j := 0; j < n; j++ { // j represents the Y value we are evaluating at
		uni_f[j] = make([]kyber.Scalar, d_1) // Adjusted to store all coefficients up to degree d_1

		for i := 0; i < d_1; i++ {
			temp := g.G1().Scalar().Zero()

			if j == 0 {
				uni_f[j][i] = f_x[i][0]
			} else {
				for k := 0; k < d_2; k++ {
					yToK := Pow(k, g.G1().Scalar().SetInt64(int64(j)), nil, g)
					coeff := g.G1().Scalar().Mul(f_x[i][k], yToK) // Multiply the bivariate coefficient with Y^k
					temp = g.G1().Scalar().Add(temp, coeff)       // Sum over all k values

				}

				uni_f[j][i] = temp

			}

		}
	}

	return uni_f
}

// Pow computes the power of a given base raised to a specified exponent within a specific group.
// exp is the exponent, base is the base value, and group represents the eliptic curve working with.
func Pow(exp int, base kyber.Scalar, e kyber.Scalar, group *bn256.Suite) kyber.Scalar {
	// Initialize a variable power with the value of 1 in the group
	power := group.G1().Scalar().One()

	// Set a temporary variable temp with the value of the base
	temp := group.G1().Scalar().Set(base)

	// Iterate exp times, multiplying the result by the base in each iteration
	for i := 0; i < exp; i++ {
		power = power.Mul(power, temp) // Multiply the result by the base
	}

	// Return the result of the power operation
	return power
}
