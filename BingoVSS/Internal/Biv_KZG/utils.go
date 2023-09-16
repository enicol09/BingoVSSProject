package biv_kzg

import (
	"fmt"
	"math/big"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
)

const debug = 0

// calculateTrapdoorValues calculates trapdoor values for a given point g_i within a specific group.
// pairing is the pairing suite, g_i is the base point, group is the group identifier (1 or 2), l is the length of the trapdoor, and t is a scalar value.
func calculateTrapdoorValues(pairing *bn256.Suite, g_i kyber.Point, group, l int, t kyber.Scalar) ([]kyber.Point, error) {
	// Initialize a slice gTrapdoor to store the trapdoor values, with length l
	gTrapdoor := make([]kyber.Point, l)

	// Set the first trapdoor value to g_i
	gTrapdoor[0] = g_i

	// Iterate from 1 to l-1 to calculate the remaining trapdoor values
	for i := 1; i < l; i++ {
		// Check the group identifier to determine whether to use G1 or G2
		if group == 1 {

			// Set index_s to the integer value i, and calculate t raised to the power of i
			index_s := pairing.G1().Scalar().SetInt64(int64(i))
			t_in_power := Pow(i, t, index_s, pairing)

			// Multiply the base point g_i by t_in_power to calculate the trapdoor value, and store it in gTrapdoor[i]
			gTrapdoor[i] = pairing.G1().Point().Mul(t_in_power, g_i)
		} else {

			// Similar to the above, but using G2 instead of G1
			index_s := pairing.G2().Scalar().SetInt64(int64(i))
			t_in_power := Pow(i, t, index_s, pairing)
			gTrapdoor[i] = pairing.G2().Point().Mul(t_in_power, g_i)
		}
	}

	// Return the calculated trapdoor values
	return gTrapdoor, nil
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

	if debug == 1 {
		powBytes, _ := power.MarshalBinary()
		powBigInt := new(big.Int).SetBytes(powBytes)
		fmt.Println("The power result will be: ", powBigInt)
	}

	// Return the result of the power operation
	return power
}

// subPoly performs the subtraction of a scalar value y from the constant term of a given polynomial f.
func subPoly(f []kyber.Scalar, y kyber.Scalar, group *bn256.Suite) []kyber.Scalar {
	// Create a new slice q with the same length as f, to store the result of the subtraction
	q := make([]kyber.Scalar, len(f))
	for i := 0; i < len(f); i++ {
		q[i] = group.G1().Scalar().Set(f[i])
	}

	if debug == 1 {
		polBytes, _ := q[0].MarshalBinary()
		polBigInt := new(big.Int).SetBytes(polBytes)
		fmt.Println("Polynomial value of q[0] before := ", polBigInt)
	}

	// Subtract y from the constant term of the polynomial (q[0])
	q[0] = group.G1().Scalar().Sub(q[0], y)

	if debug == 1 {
		polBytes, _ := q[0].MarshalBinary()
		polBigInt := new(big.Int).SetBytes(polBytes)
		fmt.Println("Polynomial value of q[0] after subtraction := ", polBigInt)
	}

	// Return the resulting polynomial after subtraction
	return q
}

// DivPoly performs polynomial division of two polynomials n (numerator) and d (denominator).
// It returns the quotient q and remainder rem of the division.
func DivPoly(n, d []kyber.Scalar, group *bn256.Suite) ([]kyber.Scalar, []kyber.Scalar) {
	// Initialize the quotient q with the appropriate length
	q := make([]kyber.Scalar, len(n)-len(d)+1)
	for i := range q {
		q[i] = group.G1().Scalar().Zero()
	}

	// Initialize the remainder rem by copying the numerator n
	rem := make([]kyber.Scalar, len(n))
	copy(rem, n)

	// Continue dividing as long as the degree of the remainder is greater than or equal to the degree of the denominator
	for len(rem) >= len(d) {
		// Calculate the leading coefficient of the current quotient term
		l := group.G1().Scalar().Div(rem[len(rem)-1], d[len(d)-1])

		// Determine the index of the current quotient term
		ind := len(rem) - len(d)

		// Store the current quotient term in q
		q[ind] = l

		// Multiply the current quotient term by the denominator and subtract from the remainder
		for i := len(d) - 1; i >= 0; i-- {
			mulVal := group.G1().Scalar().Mul(d[i], l)
			rem[ind+i] = group.G1().Scalar().Sub(rem[ind+i], mulVal)
		}

		// Remove leading zero coefficients from the remainder
		for len(rem) > 0 && rem[len(rem)-1].Equal(group.G1().Scalar().Zero()) {
			rem = rem[:len(rem)-1]
		}
	}

	// Return the quotient and remainder of the division
	return q, rem
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

func createUnivariatePolynomials(ts *KzgSetup, f_x [][]kyber.Scalar, d_1 int, d_2 int) [][]kyber.Scalar {

	// Create a 2D array to store the univariate polynomials
	uni_f := make([][]kyber.Scalar, d_2)

	// Initialize the phi array
	for j := 0; j < d_2; j++ {
		uni_f[j] = make([]kyber.Scalar, d_1)
		for i := 0; i < d_1; i++ {
			uni_f[j][i] = ts.g.G1().Scalar().Zero()
		}
	}

	// Extract the univariate polynomials
	for j := 0; j < d_2; j++ {
		for i := 0; i < d_1; i++ {
			uni_f[j][i] = f_x[i][j]
		}
	}

	return uni_f
}

// func evaluatePolynomialPoint(scalar, a kyber.Scalar, suite *bn256.Suite) kyber.Scalar {
// 	// Initialize the result r to zero
// 	r := suite.G1().Scalar().Zero()

// 	// Initialize a temporary variable tmp to one, to be used for calculating the power of x
// 	tmp := suite.G1().Scalar().One()

// 	// Multiply the current coefficient by the current power of x (stored in tmp)
// 	term := suite.G1().Scalar().Mul(tmp, scalar)

// 	// Add the result to the current value of r
// 	r = suite.G1().Scalar().Add(r, term)

// 	// Multiply tmp by x, increasing the power of x for the next iteration
// 	tmp = suite.G1().Scalar().Mul(tmp, a)

// 	// Return the result of the evaluation
// 	return r
// }

func interpolatePolynomial(f_1 [][]kyber.Scalar, a_f1_x [][]kyber.Scalar, d_1, d_2 int) [][]kyber.Scalar {

	for i := 0; i < d_2; i++ {
		for j := 0; j < d_1; j++ {
			f_1[j][i] = a_f1_x[i][j]

		}
	}

	return f_1
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

func adjustBivariateCoefficients(f_1 [][]kyber.Scalar, d_2 int, co []kyber.Scalar, group *bn256.Suite) [][]kyber.Scalar {

	for i := 0; i < len(co); i++ {
		f_1[i][0] = co[i]
	}

	return f_1
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

func evaluatePolynomialAt(phi []kyber.Scalar, value kyber.Scalar) kyber.Scalar {
	result := phi[0].Clone().Zero()

	currentValue := value.Clone().One()
	for _, coeff := range phi {
		result.Add(result, coeff.Clone().Mul(coeff, currentValue))
		currentValue.Mul(currentValue, value)
	}

	return result
}
