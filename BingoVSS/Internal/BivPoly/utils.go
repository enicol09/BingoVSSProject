package bivpoly

import (
	"bytes"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
)

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

func vandermonde(x []kyber.Scalar, degree int) [][]kyber.Scalar {
	suite := bn256.NewSuite()
	rows := len(x)
	cols := degree + 1
	vMatrix := make([][]kyber.Scalar, rows)
	for i := 0; i < rows; i++ {
		vMatrix[i] = make([]kyber.Scalar, cols)
		v := suite.G1().Scalar().One()
		for j := 0; j < cols; j++ {
			vMatrix[i][j] = v.Clone()
			v.Mul(v, x[i])
		}
	}
	return vMatrix
}

func solveLinearSystem(vMatrix [][]kyber.Scalar, y []kyber.Scalar) []kyber.Scalar {
	suite := bn256.NewSuite()
	rows := len(vMatrix)
	cols := len(vMatrix[0])

	// Construct augmented matrix
	augmentedMatrix := make([][]kyber.Scalar, rows)
	for i := 0; i < rows; i++ {
		augmentedMatrix[i] = make([]kyber.Scalar, cols+1)
		copy(augmentedMatrix[i], vMatrix[i])
		augmentedMatrix[i][cols] = y[i]
	}

	// Gaussian elimination
	for i := 0; i < rows; i++ {
		for j := i + 1; j < rows; j++ {
			factor := suite.G1().Scalar().Div(augmentedMatrix[j][i], augmentedMatrix[i][i])
			for k := i; k <= cols; k++ {
				temp := suite.G1().Scalar().Mul(augmentedMatrix[i][k], factor)
				augmentedMatrix[j][k] = suite.G1().Scalar().Sub(augmentedMatrix[j][k], temp)
			}
		}
	}

	// Back substitution
	coeffs := make([]kyber.Scalar, cols)
	for i := rows - 1; i >= 0; i-- {
		sum := suite.G1().Scalar().Zero()
		for j := i + 1; j < cols; j++ {
			temp := suite.G1().Scalar().Mul(coeffs[j], augmentedMatrix[i][j])
			sum = suite.G1().Scalar().Add(sum, temp)
		}
		coeffs[i] = suite.G1().Scalar().Sub(augmentedMatrix[i][cols], sum)
		coeffs[i].Div(coeffs[i], augmentedMatrix[i][i])
	}

	return coeffs
}

// EvaluatePolynomial evaluates a polynomial p at a given value x.
// It takes a slice of kyber.Scalar values representing the coefficients of the polynomial p,
// a kyber.Scalar value x representing the point at which to evaluate the polynomial,
// and a bn256.Suite object suite for performing arithmetic operations.
// It returns the result of the evaluation as a kyber.Scalar value.
func EvaluatePolynomial(p []kyber.Scalar, x kyber.Scalar, suite *bn256.Suite) kyber.Scalar {
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

func CreateProjectionPolynomials(g *bn256.Suite, f_x [][]kyber.Scalar, d_1 int, d_2 int, n int) [][]kyber.Scalar {

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

func CreateProjectionColumnPolynomials(g *bn256.Suite, f_x [][]kyber.Scalar, d_1 int, d_2 int, n int) [][]kyber.Scalar {

	// Create a 2D array to store the univariate polynomials
	beta_f := make([][]kyber.Scalar, n)

	// Extract the univariate polynomials for fixed i
	for j := 0; j < n; j++ { // j represents the X value we are evaluating at
		beta_f[j] = make([]kyber.Scalar, d_2) // Adjusted to store all coefficients up to degree d_2

		for i := 0; i < d_2; i++ {
			temp := g.G1().Scalar().Zero()

			if j == 0 {
				beta_f[j][i] = f_x[0][i]
			} else {
				for k := 0; k < d_1; k++ {
					xToK := Pow(k, g.G1().Scalar().SetInt64(int64(j)), nil, g) // You will need to implement or provide this Pow function
					coeff := g.G1().Scalar().Mul(f_x[k][i], xToK)              // Multiply the bivariate coefficient with X^k (X is fixed to i)
					temp = g.G1().Scalar().Add(temp, coeff)                    // Sum over all k values
				}
				beta_f[j][i] = temp
			}
		}
	}
	return beta_f
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
