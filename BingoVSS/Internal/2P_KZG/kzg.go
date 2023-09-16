package polytwo_kzg

import (
	"fmt"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
)

// kzgSetup is used to set down the bilinear pairing setups
type kzgSetup struct {
	t_1  []kyber.Point
	t_2  []kyber.Point
	t_Up []kyber.Point
	g    *bn256.Suite
	gUp  kyber.Point
}

/*
This function is being utilized to represent the setup of the bilinear pairings used by the KZG commitments. More specifically it gets the generators both from G1 and G2 of bn256 eliptic curve and creates the g^t^i
*/
func NewKzgSetup(l int, pairing *bn256.Suite) (*kzgSetup, error) {

	// First Step: Compute the random value of τ, which we called trapdoor
	t := pairing.G1().Scalar().SetInt64(2)
	//Pick(pairing.RandomStream()) //choose random for beginning
	x := pairing.G1().Scalar().SetInt64(2) //choose random for next

	g1 := pairing.G1().Point().Base() //generate the base generator of Group_1
	g2 := pairing.G2().Point().Base() //generate the base generator of Group_2
	gUp := pairing.G1().Point().Mul(x, g1)

	gTrapdoorG1, err := calculateTrapdoorValues(pairing, g1, 1, l, t)
	gTrapdoorG2, err_2 := calculateTrapdoorValues(pairing, g2, 2, l, t)
	gTrapdoorGup, err_3 := calculateTrapdoorValues(pairing, gUp, 1, l, t)

	if err != nil || err_2 != nil || err_3 != nil {
		return nil, fmt.Errorf("Wrong computations")
	}

	return &kzgSetup{gTrapdoorG1, gTrapdoorG2, gTrapdoorGup, pairing, gUp}, nil
}

/* This function is being utilized to do the commitment of the polynomial */
func KZGCommits(ts *kzgSetup, f_1 []kyber.Scalar, f_2 []kyber.Scalar) kyber.Point {
	c_1 := evaluatePolyTrap_f1(ts, f_1)  // evaluate polynomial at a specific point of the trapdoor
	c_2 := evaluatePolyTrap_f2(ts, f_2)  // evaluate polynomial at a specific point of the trapdoor
	c := ts.g.G1().Point().Add(c_1, c_2) //produce the commitment
	return c
}

// evaluatePolyTrap evaluates a polynomial q at specific trapdoor values provided in the kzgSetup structure ts.
// It returns the result of the evaluation as a point c.
func evaluatePolyTrap_f1(ts *kzgSetup, q []kyber.Scalar) kyber.Point {
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

// evaluatePolyTrap evaluates a polynomial q at specific trapdoor values provided in the kzgSetup structure ts.
// It returns the result of the evaluation as a point c.
func evaluatePolyTrap_f2(ts *kzgSetup, q []kyber.Scalar) kyber.Point {
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
func KZGEvaluationProof(ts *kzgSetup, f_1, f_2 []kyber.Scalar, z, y_1, y_2 kyber.Scalar) (kyber.Point, error) {
	// Compute the polynomial subtraction: Φ(X) - y
	// This represents the numerator of the quotient polynomial q(X) = ϕ(X) - y / (X - a)
	n_1 := subPoly(f_1, y_1, ts.g) //sending Φ(X), y, suite => for f_1
	n_2 := subPoly(f_2, y_2, ts.g) //sending Φ(X), y, suite => for f_1

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
			return nil, fmt.Errorf("Error: the remainder should be 0 not %v", rem_1)
		}
	}

	for _, v := range rem_2 {
		if !v.Equal(ts.g.G1().Scalar().Zero()) {
			return nil, fmt.Errorf("Error: the remainder should be 0 not %v", rem_2)
		}
	}

	// Compute the proof: e
	// This is the final evaluation proof π by evaluating the quotient polynomial q(X) at a specific point τ
	e_1 := evaluatePolyTrap_f1(ts, q_1)
	e_2 := evaluatePolyTrap_f2(ts, q_2)

	e := ts.g.G1().Point().Add(e_1, e_2)

	return e, nil
}

// KZGVerify verifies an evaluation proof for a given commitment c, evaluation y, and proof π.
// It takes a kzgSetup structure ts, a commitment point c, a proof point proof, and scalar values z (τ) and y (ϕ(a)).
// It returns a boolean value indicating whether the verification is successful.
func KZGVerify(ts *kzgSetup, c, proof kyber.Point, z, y_1, y_2 kyber.Scalar) bool {
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
	cy := ts.g.G1().Point().Add(c, y_1G1Neg)
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
