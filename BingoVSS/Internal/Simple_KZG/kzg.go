package kzg_simple

import (
	"fmt"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
)

// kzgSetup is used to set down the bilinear pairing setups
type kzgSetup struct {
	t_1 []kyber.Point
	t_2 []kyber.Point
	g   *bn256.Suite
}

/*
This function is being utilized to represent the setup of the bilinear pairings used by the KZG commitments. More specifically it gets the generators both from G1 and G2 of bn256 eliptic curve and creates the g^t^i
*/
func NewKzgSetup(l int, pairing *bn256.Suite) (*kzgSetup, error) {

	// First Step: Compute the random value of τ, which we called trapdoor
	t := pairing.G1().Scalar().Pick(pairing.RandomStream())

	g1 := pairing.G1().Point().Base() //generate the base generator of Group_1
	g2 := pairing.G2().Point().Base() //generate the base generator of Group_2

	gTrapdoorG1, err := calculateTrapdoorValues(pairing, g1, 1, l, t)
	gTrapdoorG2, err_2 := calculateTrapdoorValues(pairing, g2, 2, l, t)

	if err != nil || err_2 != nil {
		return nil, fmt.Errorf("Wrong computations")
	}

	return &kzgSetup{gTrapdoorG1, gTrapdoorG2, pairing}, nil
}

/* This function is being utilized to do the commitment of the polynomial */
func KZGCommits(ts *kzgSetup, f []kyber.Scalar) kyber.Point {
	c := evaluatePolyTrap(ts, f) // evaluate polynomial at a specific point of the trapdoor
	return c
}

// evaluatePolyTrap evaluates a polynomial q at specific trapdoor values provided in the kzgSetup structure ts.
// It returns the result of the evaluation as a point c.
func evaluatePolyTrap(ts *kzgSetup, q []kyber.Scalar) kyber.Point {
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

/* This function represents the KZG evaluation proof. It computes the evaluation proof π for a given polynomial ϕ(X) at a point a, with the result y. */
func KZGEvaluationProof(ts *kzgSetup, f []kyber.Scalar, z, y kyber.Scalar) (kyber.Point, error) {
	// Compute the polynomial subtraction: Φ(X) - y
	// This represents the numerator of the quotient polynomial q(X) = ϕ(X) - y / (X - a)
	n := subPoly(f, y, ts.g) //sending Φ(X), y, suite

	// Compute the denominator: X - a
	// This represents the denominator of the quotient polynomial q(X)
	d := []kyber.Scalar{ts.g.G1().Scalar().Neg(z), ts.g.G1().Scalar().One()}

	// Compute the quotient: q(X) = ϕ(X) - y / (X - a)
	// This computes the actual quotient polynomial q(X) by dividing the numerator by the denominator
	q, rem := DivPoly(n, d, ts.g)

	// Check if the remainder is zero (all elements are zero)
	// This ensures that the division was exact, and there is no remainder, as per the polynomial remainder theorem
	for _, v := range rem {
		if !v.Equal(ts.g.G1().Scalar().Zero()) {
			return nil, fmt.Errorf("Error: the remainder should be 0 not %v", rem)
		}
	}

	// Compute the proof: e
	// This is the final evaluation proof π by evaluating the quotient polynomial q(X) at a specific point τ
	e := evaluatePolyTrap(ts, q)

	return e, nil
}

// KZGVerify verifies an evaluation proof for a given commitment c, evaluation y, and proof π.
// It takes a kzgSetup structure ts, a commitment point c, a proof point proof, and scalar values z (τ) and y (ϕ(a)).
// It returns a boolean value indicating whether the verification is successful.
func KZGVerify(ts *kzgSetup, c, proof kyber.Point, z, y kyber.Scalar) bool {
	// (4) Extracting value  t_2[1] - equivalent to [τ] value at 2
	s2 := ts.t_2[1]

	// (5) Calculating [z]-(τ) and negating it
	zG2Neg := ts.g.G2().Point().Neg(ts.g.G2().Point().Mul(z, nil))
	// (5) Calculating [τ]₂ - [z]₂
	sz := ts.g.G2().Point().Add(s2, zG2Neg)

	// (6) Calculating [y]-(f(a)) and negating it
	yG1Neg := ts.g.G1().Point().Neg(ts.g.G1().Point().Mul(y, nil))
	// (6) Calculating c - [y](1) (g^f(τ) - y)
	cy := ts.g.G1().Point().Add(c, yG1Neg)

	// Base point H in G2
	h := ts.g.G2().Point().Base()

	// Pairings
	// (7) Calculate the pairing e1 = e(g^ϕ(τ) - y, g)
	e1 := ts.g.Pair(cy, h)
	// (7) Calculate the pairing e2 = e(g^q(τ), g^(τ - a))
	e2 := ts.g.Pair(proof, sz)

	// Check that the pairings e1 and e2 are equal, verifying that q(X) = ϕ(X) - y / (X - a) at X = τ
	return e1.Equal(e2)
}
