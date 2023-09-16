package bivpoly

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
)

// PriShare represents a private share.
type PriShare struct {
	I int          // Index of the private share
	V kyber.Scalar // Value of the private polynomial in φ(χ)
}

func (p *PriShare) String() string {
	return fmt.Sprintf("{%d:%s}", p.I, p.V)
}

// PriPoly represents a secret sharing polynomial.
type PriPoly struct {
	g     *bn256.Suite   // Cryptographic group
	f_x   []kyber.Scalar // Coefficients of the polynomial
	f_h_x []kyber.Scalar
}

// BivPoly represents a bivariate polynomial
type BivPoly struct {
	g      *bn256.Suite     // Cryptographic group
	coeffs [][]kyber.Scalar // Coefficients of the polynomial
	d_1    int              //degree in x
	d_2    int              //degree in y
}

// PrivBivPoly represents the secret sharing bivariate polynomial
type PrivBivPoly struct {
	g      *bn256.Suite     // Cryptographic group
	coeffs [][]kyber.Scalar // Coefficients of the polynomial
	d_1    int
	d_2    int
}

// NewPrivBivPoly creates a new secret sharing bivariate polynomial. (as defined in the paper's algo)
func NewPrivBivPoly(g *bn256.Suite, poly *BivPoly, d_1, d_2 int, secrets []kyber.Scalar) *PrivBivPoly {

	//First Step perform Vandermonde to satisfy that φ(-κ,0) = S_k. This will eventually return coefficients
	// that when evaluated to the specific points (-κ) will give back the secrets
	secret_coefficients := recoverVandermonde(g, secrets, d_1)

	//Second Step: As soon as we received the new coeffs need to adjust them to the given random polynom
	poly.adjustCoefficients(d_2, secret_coefficients, g)

	//Third_Step: Create Projection Polynomials
	uni_f := CreateProjectionPolynomials(g, poly.coeffs, d_1, d_2, d_2)

	//Fourth_Step: Interpolate the polynomial to become again a bivariate one.
	final := interpolatePolynomial(poly.coeffs, uni_f, d_1, d_2)

	//Final_Step create the new bivariate polynomial and return it.
	return &PrivBivPoly{g: g, coeffs: final, d_1: d_1 - 1, d_2: d_2 - 1}

}

func findNegShares(poly []kyber.Scalar, n int, g *bn256.Suite) []kyber.Scalar {
	shares := make([]kyber.Scalar, n)

	for i := 0; i < n; i++ {
		neg_i := g.G1().Scalar().Neg(g.G1().Scalar().SetInt64(int64(i)))
		shares[i] = EvaluatePolynomial(poly, neg_i, g)
	}
	return shares
}

func interpolatePolynomial(f_1 [][]kyber.Scalar, a_f1_x [][]kyber.Scalar, d_1, d_2 int) [][]kyber.Scalar {

	for i := 0; i < d_2; i++ {
		for j := 0; j < d_1; j++ {
			f_1[j][i] = a_f1_x[i][j]

		}
	}

	return f_1
}

// Threshold returns the secret sharing threshold.
func (p BivPoly) ReturnCoefficients() [][]kyber.Scalar {
	return p.coeffs
}

// Threshold returns the secret sharing threshold.
func (p PrivBivPoly) ReturnCoefficients() [][]kyber.Scalar {
	return p.coeffs
}

// Threshold returns the secret sharing threshold.
func (p *BivPoly) adjustCoefficients(d_2 int, coeff []kyber.Scalar, g *bn256.Suite) {

	for i := 0; i < len(coeff); i++ {
		p.coeffs[i][0] = coeff[i]
	}
}

func recoverVandermonde(g *bn256.Suite, s []kyber.Scalar, d_1 int) []kyber.Scalar {

	//set_data_points
	//set_data_points_for_x

	x := make([]kyber.Scalar, d_1)

	// remember that we need the negative values

	for i := 0; i < d_1; i++ {
		x[i] = g.G1().Scalar().Neg(g.G1().Scalar().SetInt64((int64)(i)))
	}

	//set_data_points_for_y
	y := make([]kyber.Scalar, d_1)

	for j := 0; j < d_1; j++ {
		if j < len(s) {
			y[j] = s[j]
		} else {
			y[j] = g.G1().Scalar().Pick(g.RandomStream())
		}

	}

	// perform vandermonde on this
	degree := len(x) - 1

	// Generate Vandermonde matrix
	vMatrix := vandermonde(x, degree)

	// Solve the system of linear equations
	coeffs := solveLinearSystem(vMatrix, y)

	return coeffs

}

func RecoverVandermondePos(g *bn256.Suite, s []kyber.Scalar, d_1 int) []kyber.Scalar {

	//set_data_points
	//set_data_points_for_x

	x := make([]kyber.Scalar, d_1)

	// remember that we need the negative values

	for i := 0; i < d_1; i++ {
		x[i] = g.G1().Scalar().SetInt64((int64)(i))
	}

	//set_data_points_for_y
	y := make([]kyber.Scalar, d_1)

	for j := 0; j < d_1; j++ {
		if j < len(s) {
			y[j] = s[j]
		} else {
			y[j] = g.G1().Scalar().Pick(g.RandomStream())
		}

	}

	// perform vandermonde on this
	degree := len(x) - 1

	// Generate Vandermonde matrix
	vMatrix := vandermonde(x, degree)

	// Solve the system of linear equations
	coeffs := solveLinearSystem(vMatrix, y)

	return coeffs

}

func RecoverVandermondeGivenX(g *bn256.Suite, xg []kyber.Scalar, s []kyber.Scalar, d_1 int) []kyber.Scalar {

	//set_data_points
	//set_data_points_for_x

	x := make([]kyber.Scalar, d_1)
	for j := 0; j < d_1; j++ {
		if j < len(xg) {
			x[j] = xg[j]
		} else {
			fmt.Println("elia")
			x[j] = g.G1().Scalar().SetInt64(int64(j))
		}

	}

	//set_data_points_for_y
	y := make([]kyber.Scalar, d_1)

	for j := 0; j < d_1; j++ {
		if j < len(s) {
			y[j] = s[j]
		} else {
			y[j] = g.G1().Scalar().Pick(g.RandomStream())
		}

	}

	// perform vandermonde on this
	degree := len(x) - 1

	// Generate Vandermonde matrix
	vMatrix := vandermonde(x, degree)

	// Solve the system of linear equations
	coeffs := solveLinearSystem(vMatrix, y)

	return coeffs

}

// NewBivPoly creates a new bivariate polynomial using the provided
// cryptographic group, the degree in x (d_1) and the degree in y (d_2)
func NewBivPolyRandom(g *bn256.Suite, d_1, d_2 int, rand cipher.Stream) *BivPoly {

	coeffs := make([][]kyber.Scalar, d_1)

	for i := 0; i < d_1; i++ {
		coeffs[i] = make([]kyber.Scalar, d_2)
		for j := 0; j < d_2; j++ {
			coeffs[i][j] = g.G1().Scalar().Pick(rand)
		}
	}

	return &BivPoly{g: g, coeffs: coeffs, d_1: d_1 - 1, d_2: d_2 - 1}
}

// NewPriPoly creates a new secret sharing polynomial that the dealer shares with the participants.
func NewPriPoly(group *bn256.Suite, f int, coeffs, coeffs_2 []kyber.Scalar, rand cipher.Stream) *PriPoly {

	return &PriPoly{g: group, f_x: coeffs, f_h_x: coeffs_2}
}

func NewPriShare(i int, val kyber.Scalar) *PriShare {

	return &PriShare{I: i, V: val}
}

// NewPriPoly creates a new secret sharing polynomial using the provided
// cryptographic group, the secret sharing threshold t, and the secret to be
// shared s. If s is nil, a new s is chosen using the provided randomness
// stream rand.
func NewBivPoly(g *bn256.Suite, f int, s kyber.Scalar, rand cipher.Stream) *BivPoly {
	d_1 := 2*f + 1
	d_2 := f + 1

	coeffs := make([][]kyber.Scalar, d_1) //this represents the Φ(Χ)
	coeffs[0] = make([]kyber.Scalar, d_2)
	coeffs[1] = make([]kyber.Scalar, d_2)
	coeffs[2] = make([]kyber.Scalar, d_2)
	coeffs[3] = make([]kyber.Scalar, d_2)
	coeffs[4] = make([]kyber.Scalar, d_2)

	coeffs[0][0] = g.G1().Scalar().SetInt64(2)
	coeffs[0][1] = g.G1().Scalar().SetInt64(2)
	coeffs[0][2] = g.G1().Scalar().SetInt64(2)

	coeffs[1][0] = g.G1().Scalar().SetInt64(0)
	coeffs[1][1] = g.G1().Scalar().SetInt64(1)
	coeffs[1][2] = g.G1().Scalar().SetInt64(2)

	coeffs[2][0] = g.G1().Scalar().SetInt64(0)
	coeffs[2][1] = g.G1().Scalar().SetInt64(1)
	coeffs[2][2] = g.G1().Scalar().SetInt64(1)

	coeffs[3][0] = g.G1().Scalar().SetInt64(0)
	coeffs[3][1] = g.G1().Scalar().SetInt64(1)
	coeffs[3][2] = g.G1().Scalar().SetInt64(0)

	coeffs[4][0] = g.G1().Scalar().SetInt64(0)
	coeffs[4][1] = g.G1().Scalar().SetInt64(1)
	coeffs[4][2] = g.G1().Scalar().SetInt64(0)

	return &BivPoly{g: g, coeffs: coeffs, d_1: 2*f + 1, d_2: f + 1}
}

// Coefficients return the list of coefficients representing p.
func (p *PriPoly) Coefficients() []kyber.Scalar {
	return p.f_x
}

func (p *PriPoly) Coefficients_2() []kyber.Scalar {
	return p.f_h_x
}

// RecoverSecret reconstructs the shared secret p(0) from a list of private
// shares using Lagrange interpolation.
func RecoverSecret(g *bn256.Suite, shares []*PriShare, t, n int) (kyber.Scalar, error) {
	x, y := xyScalar(g, shares, t, n)
	if len(x) < t {
		return nil, errors.New("share: not enough shares to recover secret")
	}

	acc := g.G1().Scalar().Zero()
	num := g.G1().Scalar()
	den := g.G1().Scalar()
	tmp := g.G1().Scalar()

	for i, xi := range x {
		yi := y[i]
		num.Set(yi)
		den.One()
		for j, xj := range x {
			if i == j {
				continue
			}
			num.Mul(num, xj)
			den.Mul(den, tmp.Sub(xj, xi))
		}
		acc.Add(acc, num.Div(num, den))
	}

	return acc, nil
}

type byIndexScalar []*PriShare

func (s byIndexScalar) Len() int           { return len(s) }
func (s byIndexScalar) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byIndexScalar) Less(i, j int) bool { return s[i].I < s[j].I }

// xyScalar returns the list of (x_i, y_i) pairs indexed. The first map returned
// is the list of x_i and the second map is the list of y_i, both indexed in
// their respective map at index i.
func xyScalar(g *bn256.Suite, shares []*PriShare, t, n int) (map[int]kyber.Scalar, map[int]kyber.Scalar) {
	// we are sorting first the shares since the shares may be unrelated for
	// some applications. In this case, all participants needs to interpolate on
	// the exact same order shares.
	sorted := make([]*PriShare, 0, n)
	for _, share := range shares {
		if share != nil {
			sorted = append(sorted, share)
		}
	}
	sort.Sort(byIndexScalar(sorted))

	x := make(map[int]kyber.Scalar)
	y := make(map[int]kyber.Scalar)
	for _, s := range sorted {
		if s == nil || s.V == nil || s.I < 0 {
			continue
		}
		idx := s.I
		x[idx] = g.G1().Scalar().SetInt64(int64(idx + 1))
		y[idx] = s.V
		if len(x) == t {
			break
		}
	}
	return x, y
}

// PubShare represents a public share, this is equivalent to a row projection evaluation
type PubShare struct {
	I int         // Index of the public share
	V kyber.Point // Value of the public share
}

// PubPoly represents a public commitment polynomial to a secret sharing polynomial.
type PubPoly struct {
	g       *bn256.Suite  // Cryptographic group
	b       kyber.Point   // Base point, nil for standard base
	commits []kyber.Point // Commitments to coefficients of the secret sharing polynomial
}

// NewPubPoly creates a new public commitment polynomial.
func NewPubPoly(g *bn256.Suite, b kyber.Point, commits []kyber.Point) *PubPoly {
	return &PubPoly{g, b, commits}
}

// Info returns the base point and the commitments to the polynomial coefficients.
func (p *PubPoly) Info() (base kyber.Point, commits []kyber.Point) {
	return p.b, p.commits
}

// Threshold returns the secret sharing threshold.
func (p *PubPoly) Threshold() int {
	return len(p.commits)
}

// Commit returns the secret commitment p(0), i.e., the constant term of the polynomial.
func (p *PubPoly) Commit() kyber.Point {
	return p.commits[0].Clone()
}

// Eval computes the public share v = p(i).
func (p *PubPoly) Eval(i int) *PubShare {
	xi := p.g.G1().Scalar().SetInt64(1 + int64(i)) // x-coordinate of this share
	v := p.g.Point().Null()
	for j := p.Threshold() - 1; j >= 0; j-- {
		v.Mul(xi, v)
		v.Add(v, p.commits[j])
	}
	return &PubShare{i, v}
}

// Equal checks equality of two public commitment polynomials p and q. If p and
// q are trivially unequal (e.g., due to mismatching cryptographic groups),
// this routine returns in variable time. Otherwise it runs in constant time
// regardless of whether it eventually returns true or false.
func (p *PubPoly) Equal(q *PubPoly) bool {
	if p.g.String() != q.g.String() {
		return false
	}
	b := 1
	for i := 0; i < p.Threshold(); i++ {
		pb, _ := p.commits[i].MarshalBinary()
		qb, _ := q.commits[i].MarshalBinary()
		b &= subtle.ConstantTimeCompare(pb, qb)
	}
	return b == 1
}

func LagrangeInterpolation(suite *bn256.Suite, points []kyber.Scalar, x kyber.Scalar) kyber.Scalar {
	n := len(points)
	result := suite.G1().Scalar().Zero()

	for i := 0; i < n; i++ {
		term := suite.G1().Scalar().Set(points[i])
		for j := 0; j < n; j++ {
			if i != j {
				numerator := suite.G1().Scalar().Sub(x, suite.G1().Scalar().SetInt64(int64(j)))
				denominator := suite.G1().Scalar().Sub(suite.G1().Scalar().SetInt64(int64(i)), suite.G1().Scalar().SetInt64(int64(j)))
				factor := suite.G1().Scalar().Div(numerator, denominator)
				term = suite.G1().Scalar().Mul(term, factor)
			}
		}
		result = suite.G1().Scalar().Add(result, term)
	}

	return result
}
