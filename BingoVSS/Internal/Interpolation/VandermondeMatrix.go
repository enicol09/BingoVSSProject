package interpolation

import (
	"math"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"

	"gonum.org/v1/gonum/mat"
)

// createVandermonde generates a Vandermonde matrix for a given set of x-values and a specified degree.
// The Vandermonde matrix is used in polynomial interpolation to solve for the coefficients of the polynomial.
// Websites := https://en.wikipedia.org/wiki/Vandermonde_matrix,
// https://mathworld.wolfram.com/VandermondeMatrix.html
// https://nhigham.com/2021/06/15/what-is-a-vandermonde-matrix/
func createVandermonde(xValues []float64, d_1 int) *mat.Dense {
	// Get the number of x-values
	n := len(xValues)

	// Initialize a new dense matrix with dimensions n x (d_1+1)
	V := mat.NewDense(n, d_1+1, nil)

	// Populate the matrix
	// Each row corresponds to an x-value
	// Each column corresponds to a power of x, starting from 0 up to d_1
	for i := 0; i < n; i++ {
		for j := 0; j <= d_1; j++ {
			// Set the matrix entry at (i, j) to xValues[i] raised to the power of j
			V.Set(i, j, math.Pow(xValues[i], float64(j)))
		}
	}

	// Return the populated Vandermonde matrix
	return V
}

// vandermonde constructs a Vandermonde matrix for a given vector of kyber.Scalar values x and a specified degree.
// The resulting matrix will have a size of len(x) x (degree+1).
func vandermonde(x []kyber.Scalar, degree int) [][]kyber.Scalar {
	// Initializing the bn256 pairing suite.
	suite := bn256.NewSuite()
	rows := len(x)
	cols := degree + 1

	// Create an empty matrix with specified dimensions.
	vMatrix := make([][]kyber.Scalar, rows)

	for i := 0; i < rows; i++ {
		// Initialize each row of the matrix.
		vMatrix[i] = make([]kyber.Scalar, cols)

		// Start with a scalar value of 1.
		v := suite.G1().Scalar().One()

		// Populate each row of the matrix with increasing powers of the current scalar from x.
		for j := 0; j < cols; j++ {
			vMatrix[i][j] = v.Clone() // Store the current value.
			v.Mul(v, x[i])            // Multiply by the scalar to increase the power for the next column.
		}
	}

	return vMatrix
}

// solveLinearSystem solves a system of linear equations represented by the Vandermonde matrix vMatrix and result vector y.
// It returns the vector of coefficients c that satisfy the equation V*c = y.
func solveLinearSystem(vMatrix [][]kyber.Scalar, y []kyber.Scalar) []kyber.Scalar {
	suite := bn256.NewSuite()
	rows := len(vMatrix)
	cols := len(vMatrix[0])

	// Constructing an augmented matrix by adding the y vector as an additional column to vMatrix.
	augmentedMatrix := make([][]kyber.Scalar, rows)
	for i := 0; i < rows; i++ {
		augmentedMatrix[i] = make([]kyber.Scalar, cols+1)
		copy(augmentedMatrix[i], vMatrix[i])
		augmentedMatrix[i][cols] = y[i]
	}

	// Gaussian elimination to transform the matrix into upper triangular form.
	for i := 0; i < rows; i++ {
		for j := i + 1; j < rows; j++ {
			factor := suite.G1().Scalar().Div(augmentedMatrix[j][i], augmentedMatrix[i][i])
			for k := i; k <= cols; k++ {
				temp := suite.G1().Scalar().Mul(augmentedMatrix[i][k], factor)
				augmentedMatrix[j][k] = suite.G1().Scalar().Sub(augmentedMatrix[j][k], temp)
			}
		}
	}

	// Back substitution to solve for the vector of coefficients.
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
