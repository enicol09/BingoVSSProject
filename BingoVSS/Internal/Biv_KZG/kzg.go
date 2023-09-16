package biv_kzg

import (
	poly "BingoVSS/Internal/BivPoly"
	"fmt"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
)

type Proof struct {
	id_from int
	p       kyber.Point
	y_1     kyber.Scalar
	y_2     kyber.Scalar
	c       kyber.Scalar
}

func (d Proof) ReturnP() kyber.Point {
	return d.p
}

func (d Proof) ReturnY_1() kyber.Scalar {
	return d.y_1
}

func (d Proof) ReturnY_2() kyber.Scalar {
	return d.y_2
}

func (d Proof) ReturnID() int {
	return d.id_from
}

/* This function constructs a new dealer */
func NewProof(id int, p kyber.Point, y_1, y_2, c kyber.Scalar) *Proof {

	return &Proof{id, p, y_1, y_2, c}
}

// KzgSetup is used to set down the bilinear pairing setups
type KzgSetup struct {
	t_1      []kyber.Point
	t_2      []kyber.Point
	t_Up     []kyber.Point
	g        *bn256.Suite
	x        kyber.Scalar
	gUp      kyber.Point
	g1       kyber.Point
	trap_val []kyber.Scalar
}

type KzgShareSetup struct {
	t_1      []kyber.Point
	t_2      []kyber.Point
	t_Up     []kyber.Point
	g        *bn256.Suite
	gUp      kyber.Point
	g1       kyber.Point
	trap_val []kyber.Scalar
}

func (k *KzgSetup) ReturnT_1() []kyber.Point {
	return k.t_1
}

func (k *KzgSetup) ReturnT_2() []kyber.Point {
	return k.t_2
}

func (k *KzgSetup) ReturnT_u() []kyber.Point {
	return k.t_Up
}

func (k *KzgSetup) ReturnG_1() kyber.Point {
	return k.g1
}

func (k *KzgSetup) ReturnVal() []kyber.Scalar {
	return k.trap_val
}

func (k *KzgShareSetup) ReturnSuite() *bn256.Suite {
	return k.g
}

func (k *KzgSetup) ReturnG_u() kyber.Point {
	return k.gUp
}

func NewShareSetup(t_1, t_2, t_up []kyber.Point, g *bn256.Suite, gUp, g1 kyber.Point, trap_val []kyber.Scalar) *KzgShareSetup {
	return &KzgShareSetup{t_1, t_2, t_up, g, gUp, g1, trap_val}
}

/*
This function is being utilized to represent the setup of the bilinear pairings used by the KZG commitments. More specifically it gets the generators both from G1 and G2 of bn256 eliptic curve and creates the g^t^i
*/
func NewKzgSetup(l int, pairing *bn256.Suite) (*KzgSetup, error) {

	// First Step: Compute the random value of τ, which we called trapdoor
	t := pairing.G1().Scalar().Pick(pairing.RandomStream()) //choose random for beginning
	x := pairing.G1().Scalar().Pick(pairing.RandomStream()) //choose random for next

	trap := calculateT(pairing, t, l)

	g1 := pairing.G1().Point().Base() //generate the base generator of Group_1
	g2 := pairing.G2().Point().Base() //generate the base generator of Group_2
	gUp := pairing.G1().Point().Mul(x, g1)

	gTrapdoorG1, err := calculateTrapdoorValues(pairing, g1, 1, l, t)
	gTrapdoorG2, err_2 := calculateTrapdoorValues(pairing, g2, 2, l, t)
	gTrapdoorGup, err_3 := calculateTrapdoorValues(pairing, gUp, 1, l, t)

	if err != nil || err_2 != nil || err_3 != nil {
		return nil, fmt.Errorf("Wrong computations")
	}

	return &KzgSetup{gTrapdoorG1, gTrapdoorG2, gTrapdoorGup, pairing, x, gUp, g1, trap}, nil
}

/* The purpose of the calculateT function is to compute a list (slice) of trapdoor values
based on a given value t and length l using a particular cryptographic pairing suite. */

func calculateT(pairing *bn256.Suite, t kyber.Scalar, l int) []kyber.Scalar {
	// Initialize the trapdoor slice with the specified length l.
	trapdoor := make([]kyber.Scalar, l)

	// Set the first trapdoor value to the scalar representation of 1.
	trapdoor[0] = pairing.G1().Scalar().SetInt64(int64(1))

	// For the remaining trapdoor values, compute t raised to the power of the current index.
	for i := 1; i < l; i++ {
		// Get the scalar representation of the current index.
		index_s := pairing.G1().Scalar().SetInt64(int64(i))

		// Raise t to the power of the current index and store the result.
		t_in_power := Pow(i, t, index_s, pairing)

		// Set the computed value as the next trapdoor entry.
		trapdoor[i] = t_in_power
	}

	// Return the computed trapdoor values.
	return trapdoor
}

/* This function is being utilized to do the commitment of the polynomial */
func Commits(ts *KzgSetup, f_1 [][]kyber.Scalar, f_2 [][]kyber.Scalar, d_1 int, d_2 int) ([]kyber.Point, []kyber.Scalar) {

	f_1_x := createUnivariatePolynomials(ts, f_1, d_1, d_2) //f
	f_2_x := createUnivariatePolynomials(ts, f_2, d_1, d_2) //f^

	c := make([]kyber.Point, d_2)
	coeffs := make([]kyber.Scalar, d_2)

	for i := 0; i < d_2; i++ {

		c_1, s_1 := evaluatePolyTrap_f1(ts, f_1_x[i]) // evaluate polynomial at a specific point of the trapdoor

		c_2, s_2 := evaluatePolyTrap_f2(ts, f_2_x[i]) // evaluate polynomial at a specific point of the trapdoor

		c[i] = ts.g.G1().Point().Add(c_1, c_2) //produce the commitment
		coeffs[i] = ts.g.G1().Scalar().Add(s_1, s_2)

	}

	return c, coeffs
}

/* This function is being utilized to do the commitment of the polynomial */
func KZGCommits(ts *KzgShareSetup, f_1 []kyber.Scalar, f_2 []kyber.Scalar) kyber.Point {
	c_1 := evaluatePolyTrap_f1_sh(ts, f_1) // evaluate polynomial at a specific point of the trapdoor
	c_2 := evaluatePolyTrap_f2_sh(ts, f_2) // evaluate polynomial at a specific point of the trapdoor
	c := ts.g.G1().Point().Add(c_1, c_2)   //produce the commitment

	return c
}

// evaluatePolyTrap evaluates a polynomial q at specific trapdoor values provided in the KzgSetup structure ts.
// It returns the result of the evaluation as a point c.
func evaluatePolyTrap_f1(ts *KzgSetup, q []kyber.Scalar) (kyber.Point, kyber.Scalar) {

	// Initialize the result c by multiplying the first coefficient of the polynomial q with the first trapdoor value in ts.t_1
	s := ts.trap_val[0].Clone().Mul(q[0], ts.trap_val[0])
	c := ts.t_1[0].Clone().Mul(q[0], ts.t_1[0])

	// Iterate through the remaining coefficients of the polynomial q
	for i := 1; i < len(q); i++ {
		// Multiply the current coefficient q[i] with the corresponding trapdoor value ts.t_1[i]
		sp := ts.t_1[i].Clone().Mul(q[i], ts.t_1[i])
		s_n := ts.trap_val[i].Clone().Mul(q[i], ts.trap_val[i])

		// Add the result to the current value of c
		c = c.Add(c, sp)
		s = s.Add(s, s_n) //Comment this in terms of the paper
	}

	// Return the result of the evaluation
	return c, s
}

// evaluatePolyTrap evaluates a polynomial q at specific trapdoor values provided in the KzgSetup structure ts.
// It returns the result of the evaluation as a point c.
func evaluatePolyTrap_f1_sh(ts *KzgShareSetup, q []kyber.Scalar) kyber.Point {

	// Initialize the result c by multiplying the first coefficient of the polynomial q with the first trapdoor value in ts.t_1
	c := ts.t_1[0].Clone().Mul(q[0], ts.t_1[0])
	// Iterate through the remaining coefficients of the polynomial q
	for i := 1; i < len(q); i++ {
		// Multiply the current coefficient q[i] with the corresponding trapdoor value ts.t_1[i]
		sp := ts.t_1[i].Clone().Mul(q[i], ts.t_1[i])

		// Add the result to the current value of c
		c = c.Add(c, sp)

	}

	// Return the result of the evaluation
	return c
}

// evaluatePolyTrap evaluates a polynomial q at specific trapdoor values provided in the KzgSetup structure ts.
// It returns the result of the evaluation as a point c.
func evaluatePolyTrap_f2(ts *KzgSetup, q []kyber.Scalar) (kyber.Point, kyber.Scalar) {
	// Initialize the result c by multiplying the first coefficient of the polynomial q with the first trapdoor value in ts.t_1
	c := ts.t_Up[0].Clone().Mul(q[0], ts.t_Up[0])
	s := ts.trap_val[0].Clone().Mul(q[0], ts.trap_val[0])

	// Iterate through the remaining coefficients of the polynomial q
	for i := 1; i < len(q); i++ {
		// Multiply the current coefficient q[i] with the corresponding trapdoor value ts.t_1[i]
		sp := ts.t_Up[i].Clone().Mul(q[i], ts.t_Up[i])
		sn := ts.trap_val[i].Clone().Mul(q[i], ts.trap_val[i])

		// Add the result to the current value of c
		c = c.Add(c, sp)
		s = s.Add(s, sn)
	}

	s = s.Mul(ts.x, s)
	// Return the result of the evaluation
	return c, s
}

// evaluatePolyTrap evaluates a polynomial q at specific trapdoor values provided in the KzgSetup structure ts.
// It returns the result of the evaluation as a point c.
func evaluatePolyTrap_f2_sh(ts *KzgShareSetup, q []kyber.Scalar) kyber.Point {
	// Initialize the result c by multiplying the first coefficient of the polynomial q with the first trapdoor value in ts.t_1
	c := ts.t_Up[0].Clone().Mul(q[0], ts.t_Up[0])

	// Iterate through the remaining coefficients of the polynomial q
	for i := 1; i < len(q); i++ {
		// Multiply the current coefficient q[i] with the corresponding trapdoor value ts.t_1[i]
		sp := ts.t_Up[i].Clone().Mul(q[i], ts.t_Up[i])

		// Add the result to the current value of c
		c = c.Add(c, sp)

	}

	// Return the result of the evaluation
	return c
}

/* This function represents the KZG evaluation proof. It computes the evaluation proof π for a given polynomial ϕ(X) at a point a, with the result y. */
func KZGEvaluationProof(ts *KzgSetup, f_1, f_2 []kyber.Scalar, z kyber.Scalar) (kyber.Point, kyber.Scalar, kyber.Scalar, kyber.Scalar, error) {
	y_1 := evaluatePolynomial(f_1, z, ts.g)
	y_2 := evaluatePolynomial(f_2, z, ts.g)

	// Compute the polynomial subtraction: Φ(X) - y
	// This represents the numerator of the quotient polynomial q(X) = ϕ(X) - y / (X - a)
	n_1 := subPoly(f_1, y_1, ts.g) //sending Φ(X), y, suite => for f_1
	n_2 := subPoly(f_2, y_2, ts.g) //sending Φ(X), y, suite => for f_2

	// Compute the denominator: X - a
	// This represents the denominator of the quotient polynomial q(X)
	d_1 := []kyber.Scalar{ts.g.G1().Scalar().Neg(z), ts.g.G1().Scalar().One()}
	d_2 := []kyber.Scalar{ts.g.G1().Scalar().Neg(z), ts.g.G1().Scalar().One()}

	// Compute the quotient: q(X) = ϕ(X) - y / (X - a)
	// This computes the actual quotient polynomial q(X) by dividing the numerator by the denominator
	q_1, rem_1 := DivPoly(n_1, d_1, ts.g)
	q_2, rem_2 := DivPoly(n_2, d_2, ts.g)

	// Check if the remainder is zero (all elements are zero)
	// This ensures that the division was exact, and there is no remainder, as per the polynomial remainder theorem
	for _, v := range rem_1 {
		if !v.Equal(ts.g.G1().Scalar().Zero()) {
			return nil, nil, nil, nil, fmt.Errorf("Error: the remainder should be 0 not %v", rem_1)
		}
	}

	for _, v := range rem_2 {
		if !v.Equal(ts.g.G1().Scalar().Zero()) {
			return nil, nil, nil, nil, fmt.Errorf("Error: the remainder should be 0 not %v", rem_2)
		}
	}

	// Compute the proof: e
	// This is the final evaluation proof π by evaluating the quotient polynomial q(X) at a specific point τ
	e_1, s_1 := evaluatePolyTrap_f1(ts, q_1)
	e_2, s_2 := evaluatePolyTrap_f2(ts, q_2)

	e := ts.g.G1().Point().Add(e_1, e_2)
	c := ts.g.G1().Scalar().Add(s_1, s_2)

	return e, y_1, y_2, c, nil
}

/* This function represents the KZG evaluation proof. It computes the evaluation proof π for a given polynomial ϕ(X) at a point a, with the result y. */
func KZGEval(ts *KzgShareSetup, f_1, f_2 []kyber.Scalar, z kyber.Scalar) (kyber.Point, kyber.Scalar, kyber.Scalar, error) {
	y_1 := evaluatePolynomial(f_1, z, ts.g)
	y_2 := evaluatePolynomial(f_2, z, ts.g)

	// Compute the polynomial subtraction: Φ(X) - y
	// This represents the numerator of the quotient polynomial q(X) = ϕ(X) - y / (X - a)
	n_1 := subPoly(f_1, y_1, ts.g) //sending Φ(X), y, suite => for f_1
	n_2 := subPoly(f_2, y_2, ts.g) //sending Φ(X), y, suite => for f_2

	// Compute the denominator: X - a
	// This represents the denominator of the quotient polynomial q(X)
	d_1 := []kyber.Scalar{ts.g.G1().Scalar().Neg(z), ts.g.G1().Scalar().One()}
	d_2 := []kyber.Scalar{ts.g.G1().Scalar().Neg(z), ts.g.G1().Scalar().One()}

	// Compute the quotient: q(X) = ϕ(X) - y / (X - a)
	// This computes the actual quotient polynomial q(X) by dividing the numerator by the denominator
	q_1, rem_1 := DivPoly(n_1, d_1, ts.g)
	q_2, rem_2 := DivPoly(n_2, d_2, ts.g)

	// Check if the remainder is zero (all elements are zero)
	// This ensures that the division was exact, and there is no remainder, as per the polynomial remainder theorem
	for _, v := range rem_1 {
		if !v.Equal(ts.g.G1().Scalar().Zero()) {
			return nil, nil, nil, fmt.Errorf("Error: the remainder should be 0 not %v", rem_1)
		}
	}

	for _, v := range rem_2 {
		if !v.Equal(ts.g.G1().Scalar().Zero()) {
			return nil, nil, nil, fmt.Errorf("Error: the remainder should be 0 not %v", rem_2)
		}
	}

	// Compute the proof: e
	// This is the final evaluation proof π by evaluating the quotient polynomial q(X) at a specific point τ
	e_1 := evaluatePolyTrap_f1_sh(ts, q_1)
	e_2 := evaluatePolyTrap_f2_sh(ts, q_2)

	e := ts.g.G1().Point().Add(e_1, e_2)

	return e, y_1, y_2, nil
}

// KZGVerify verifies an evaluation proof for a given commitment c, evaluation y, and proof π.
// It takes a KzgSetup structure ts, a commitment point c, a proof point proof, and scalar values z (τ) and y (ϕ(a)).
// It returns a boolean value indicating whether the verification is successful.
func KZGVerify(ts *KzgShareSetup, A []kyber.Point, i int, proof kyber.Point, z, y_1, y_2 kyber.Scalar) bool {
	// (4) Extracting s2 from t_2[1] - equivalent to [τ]₂
	s2 := ts.t_2[1]

	// (5) Calculating [z]₂ (τ) and negating it
	zG2Neg := ts.g.G2().Point().Neg(ts.g.G2().Point().Mul(z, nil))
	// (5) Calculating [τ]₂ - [z]₂
	sz := ts.g.G2().Point().Add(s2, zG2Neg)

	// (6) Calculating [y]₁ (ϕ(a)) and negating it
	y_1G1Neg := ts.g.G1().Point().Neg(ts.g.G1().Point().Mul(y_1, nil))
	y_2G1Neg := ts.g.G1().Point().Neg(ts.g.G1().Point().Mul(y_2, ts.gUp))
	// (6) Calculating c - [y]₁ (g^ϕ(τ) - y)
	cy := ts.g.G1().Point().Add(A[i], y_1G1Neg)
	ct := ts.g.G1().Point().Add(cy, y_2G1Neg)

	// Base point H in 𝔾₂
	h := ts.g.G2().Point().Base()

	// Pairings
	// (7) Calculate the pairing e1 = e(g^ϕ(τ) - y, g)
	e1 := ts.g.Pair(ct, h)
	// (7) Calculate the pairing e2 = e(g^q(τ), g^(τ - a))
	e2 := ts.g.Pair(proof, sz)

	// Check that the pairings e1 and e2 are equal, verifying that q(X) = ϕ(X) - y / (X - a) at X = τ
	return e1.Equal(e2)
}

/*
	The goal of the function is to evaluate the polynomial commitments at the points (partial points)
	given an array of distinct points.
*/

func PartialEval(trap *KzgSetup, c []kyber.Point, co, vn []kyber.Scalar) []kyber.Point {

	// Initialize a slice to store the results of polynomial evaluations.
	results := make([]kyber.Point, len(vn))

	// Evaluate the polynomial at each point and store the result in the results slice.
	for i := 0; i < len(vn); i++ {
		// Get the scalar representation of integer i.
		x := trap.g.G1().Scalar().SetInt64(int64(i))

		// Evaluate the polynomial at point x.
		y := evaluatePolynomialAt(co, x)

		// Multiply the evaluation result with a point on the curve to get the commitment
		// and store it in the results slice.
		results[i] = trap.g1.Clone().Mul(y, trap.g1)
	}

	// Return the results of polynomial evaluations.
	return results
}

func GetProofs(proofs []Proof, vn []kyber.Scalar, setup *KzgSetup, d_2 int) ([]kyber.Point, []kyber.Scalar, []kyber.Scalar) {

	//β(X) ← Interpolate {(wi, yi)}i∈[d1+1]
	y_i := make([]kyber.Scalar, d_2+1)
	y_j := make([]kyber.Scalar, d_2+1)
	x_i := make([]kyber.Scalar, d_2+1)
	c_i := make([]kyber.Scalar, d_2+1)
	n := 0

	for i := 0; i < len(proofs); i++ {
		if proofs[i].p != nil && n < d_2+1 {
			y_i[n] = proofs[i].y_1
			y_j[n] = proofs[i].y_2
			x_i[n] = setup.g.G1().Scalar().SetInt64(int64(proofs[i].id_from))
			c_i[n] = proofs[i].c
			n++
		}
	}

	b_x := poly.RecoverVandermondeGivenX(setup.g, x_i, y_i, d_2)

	b_xj := poly.RecoverVandermondeGivenX(setup.g, x_i, y_j, d_2)

	c_r := poly.RecoverVandermondeGivenX(setup.g, x_i, c_i, d_2)

	pr := make([]kyber.Point, len(vn))
	y_1 := make([]kyber.Scalar, len(vn))
	y_2 := make([]kyber.Scalar, len(vn))

	for i := 0; i < len(vn); i++ {

		y_1[i] = evaluatePolynomialAt(b_x, vn[i])
		y_2[i] = evaluatePolynomialAt(b_xj, vn[i])
		c := evaluatePolynomialAt(c_r, vn[i])
		pr[i] = setup.g1.Clone().Mul(c, setup.g1)

	}

	return pr, y_1, y_2

}
