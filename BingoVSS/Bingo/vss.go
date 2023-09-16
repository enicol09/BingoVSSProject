package vss

import (
	poly "BingoVSS/Internal/BivPoly"
	kzg "BingoVSS/Internal/Biv_KZG"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
)

// The Suite defines the capabilities required by the bingoVss package.
type Suite struct {
	suite *bn256.Suite
}

type Secret struct {
	s    kyber.Scalar
	eval kyber.Scalar
	id   int
}

/*
	The following struct represents the Dealer that performs most of the

actions of a subprotocol of BingoShare called BingoDeal
*/
type Dealer struct {
	secretPoly      poly.PrivBivPoly
	randomPoly      poly.BivPoly
	suite           *Suite
	publicCommitsCM []kyber.Point
	CM_coeffs       []kyber.Scalar
	id              int
	sharePolys      []poly.PriPoly
	verifiers       []Verifier
}

type Verifier struct {
	polynomial poly.PriPoly
	id         int
	status     string
	rowProofs  []kzg.Proof
	CrowProofs []kzg.Proof
	VrowProofs []kzg.Proof //the verified rows proofs
	colProofs  []kzg.Proof //the verified rows proofs
}

func (s *Secret) SendSecret() kyber.Scalar {
	return s.s
}

func (v *Verifier) SendPolynomials() *poly.PriPoly {
	return &v.polynomial
}

func (v *Verifier) SendProofsRow() []kzg.Proof {
	return v.rowProofs
}

func (v *Verifier) SendProofsCol() []kzg.Proof {
	return v.colProofs
}

func (v *Verifier) SendStatus() string {
	return v.status
}

/* This function constructs a new dealer */
func NewSecret(val int, suite Suite) *Secret {
	s := suite.suite.G1().Scalar().Pick(suite.suite.RandomStream())
	eval := suite.suite.G1().Scalar().Neg(suite.suite.G1().Scalar().SetInt64((int64(val))))
	id := val
	return &Secret{s, eval, id}
}

/* This function constructs a new dealer */
func NewSuite() *Suite {
	suite := bn256.NewSuite()
	return &Suite{suite: suite}
}

/* This function constructs a new dealer */
func NewDealer() *Dealer {
	suite := NewSuite()
	return &Dealer{suite: suite, id: 0}
}

/* This function constructs a new dealer */
func NewVerifier(poly poly.PriPoly, id int, n int) *Verifier {
	proofs := make([]kzg.Proof, n)
	proofs_s := make([]kzg.Proof, n)
	proofs_ss := make([]kzg.Proof, n)
	proofs_sss := make([]kzg.Proof, n)
	return &Verifier{poly, id, "null", proofs, proofs_s, proofs_ss, proofs_sss}
}

func (d *Dealer) BingoDeal(secrets []Secret, x, y, par int, setup *kzg.KzgSetup) {

	//Select degree of the polynomial (for example purposes we pre-define this)
	d_1 := x //Degree in X
	d_2 := y //Degree in Y
	n := par //number_of_verifiers

	//Step_1: The dealer uniformly samples the polynomial Φ(X) and Φ'(Χ)
	f_x := *poly.NewBivPolyRandom(d.suite.suite, d_1+1, d_2+1, d.suite.suite.RandomStream())
	d.randomPoly = *poly.NewBivPolyRandom(d.suite.suite, d_1+1, d_2+1, d.suite.suite.RandomStream()) //φ'(Χ) is completely random

	// Need to make Φ(Χ) in a way that φ(-κ,0) = S_k
	// Τherefore we need to modify it

	secret_scalar := make([]kyber.Scalar, len(secrets))
	for i := 0; i < len(secrets); i++ {
		secret_scalar[i] = secrets[i].s
	}

	d.secretPoly = *poly.NewPrivBivPoly(d.suite.suite, &f_x, d_1+1, d_2+1, secret_scalar)

	// ThirdStep: Dealer commits the polynomials

	d.publicCommitsCM, d.CM_coeffs = kzg.Commits(setup, d.secretPoly.ReturnCoefficients(), d.randomPoly.ReturnCoefficients(), d_1+1, d_2+1)

	share_poly := make([]poly.PriPoly, n+1)
	// FourthStep: Create the projections, that means create the share-polynomials that you are giving to verifiers.
	SharePolynomials_f_x := poly.CreateProjectionPolynomials(d.suite.suite, d.secretPoly.ReturnCoefficients(), d_1+1, d_2+1, n+1)
	SharePolynomials_f_x_h := poly.CreateProjectionPolynomials(d.suite.suite, d.randomPoly.ReturnCoefficients(), d_1+1, d_2+1, n+1)

	//CreateTheSharePolynomials
	for i := 0; i < n+1; i++ {
		share_poly[i] = *poly.NewPriPoly(d.suite.suite, n, SharePolynomials_f_x[i], SharePolynomials_f_x_h[i], nil)
	}
	d.sharePolys = share_poly
	d.Broadcast()
	d.SharePolynomials()

}

func (d *Suite) ReturnSuite() *bn256.Suite {
	return d.suite
}

func (d *Dealer) ReturnSuite() Suite {
	return *d.suite
}

func (d *Dealer) Broadcast() {
	//fmt.Println("Commits", d.publicCommitsCM)
}

func (d *Dealer) SharePolynomials() {
	d.verifiers = make([]Verifier, len(d.sharePolys))
	for i := 0; i < len(d.sharePolys); i++ {
		d.verifiers[i] = *NewVerifier(d.sharePolys[i], i+1, len(d.sharePolys))
	}
}

func BingoShareDealer(secrets []Secret, d_1, d_2, n int, Id int, suite Suite, setup *kzg.KzgSetup) ([]kyber.Point, []kyber.Scalar, []Verifier) {

	d := NewDealer()
	d.BingoDeal(secrets, d_1, d_2, n, setup)

	return d.publicCommitsCM, d.CM_coeffs, d.verifiers

}

func BingoShare(verifier []Verifier, d_1, d_2, n int, id int, cm []kyber.Point, suite Suite, setup *kzg.KzgShareSetup, set *kzg.KzgSetup) {
	//Check with KZGcommit
	if verifier[id].status == "null" {
		if kzg.KZGCommits(setup, verifier[id].polynomial.Coefficients(), verifier[id].polynomial.Coefficients_2()).Equal(cm[id]) {
			verifier[id].UpdateStatus("correct polynomial")
		} else {
			verifier[id].UpdateStatus("not correct polynomials")
		}
	}

	if verifier[id].status == "correct polynomial" {
		for j := 0; j < len(verifier); j++ {
			a := suite.suite.G1().Scalar().SetInt64(int64(j))

			// Step_6 : create an evaluation proof
			proof, y_1, y_2, co, _ := kzg.KZGEvaluationProof(set, verifier[id].polynomial.Coefficients(), verifier[id].polynomial.Coefficients_2(), a)

			proof_a := kzg.NewProof(id, proof, y_1, y_2, co)

			verifier[j].rowProofs[id] = *proof_a

			verifier[id].ShareStatus("row to participant ", j) //this line 14
		}

	}

	if verifier[id].status == "has sent rows" {
		if len(verifier[id].rowProofs) > d_2+1 {
			c := 0
			for !(checkForNotNil(verifier[id].VrowProofs) == d_2+2) { //line 20
				if verifier[id].rowProofs[c].ReturnP() != nil {
					a := suite.suite.G1().Scalar().SetInt64(int64(id))
					if kzg.KZGVerify(setup, cm, c, verifier[id].rowProofs[c].ReturnP(), a, verifier[id].rowProofs[c].ReturnY_1(), verifier[id].rowProofs[c].ReturnY_2()) {
						verifier[id].VrowProofs[c] = verifier[id].rowProofs[c] //line 19
					}
				}
				c++
			}
		}

		vn := make([]kyber.Scalar, n+1)
		for i := 0; i < n+1; i++ {
			vn[i] = suite.suite.G1().Scalar().SetInt64(int64(i))
		}

		//now we can compute the columns based on that okay-> so we use get proofs
		pr, y_1, y_2 := kzg.GetProofs(verifier[id].VrowProofs, vn, set, d_2+1)
		for j := 0; j < len(verifier); j++ {
			proof_a := kzg.NewProof(id, pr[j], y_1[j], y_2[j], nil)
			verifier[j].colProofs[id] = *proof_a                  //b_j_i
			verifier[id].ShareStatus("column to participant ", j) //this line 23
		}

	}

	if verifier[id].status == "missing polynomial" { //line 26

		if len(verifier[id].colProofs) > 2*d_2+1 {
			c := 0

			for !(checkForNotNil(verifier[id].CrowProofs)-1 == 2*d_2+1) { //line 20
				if verifier[id].colProofs[c].ReturnP() != nil {
					a := suite.suite.G1().Scalar().SetInt64(int64(c))
					if kzg.KZGVerify(setup, cm, id, verifier[id].colProofs[c].ReturnP(), a, verifier[id].colProofs[c].ReturnY_1(), verifier[id].colProofs[c].ReturnY_2()) { //line 27
						verifier[id].CrowProofs[c] = verifier[id].colProofs[c] //line 19
					}
				}
				c++
			}

			a_x, a_xi := InterpolateRows(verifier[id].CrowProofs, setup, d_1+1)
			verifier[id].polynomial = *poly.NewPriPoly(setup.ReturnSuite(), d_2, a_x, a_xi, setup.ReturnSuite().RandomStream())

		}
	}

}

func InterpolateRows(proofs []kzg.Proof, set *kzg.KzgShareSetup, d_1 int) ([]kyber.Scalar, []kyber.Scalar) {
	y_i := make([]kyber.Scalar, d_1+1)
	y_j := make([]kyber.Scalar, d_1+1)
	x_i := make([]kyber.Scalar, d_1+1)

	n := 0

	for i := 0; i < len(proofs); i++ {
		if proofs[i].ReturnP() != nil && n < d_1+1 {
			y_i[n] = proofs[i].ReturnY_1()
			y_j[n] = proofs[i].ReturnY_2()
			x_i[n] = set.ReturnSuite().G1().Scalar().SetInt64(int64(proofs[i].ReturnID()))
			n++
		}
	}

	a_x := poly.RecoverVandermondeGivenX(set.ReturnSuite(), x_i, y_i, d_1)

	a_xj := poly.RecoverVandermondeGivenX(set.ReturnSuite(), x_i, y_j, d_1)

	return a_x, a_xj
}

func checkForNotNil(proof []kzg.Proof) int {
	temp := 0

	for i := 0; i < len(proof); i++ {
		if proof[i].ReturnP() != nil {
			temp++
		}

	}

	return temp
}

func (v *Verifier) UpdateStatus(msg string) {
	v.status = msg
}

func (v *Verifier) ShareStatus(msg string, i int) {
	// fmt.Println("Me with id = ", v.id-1, msg, i)
}

// func polynomialPrint(f_x [][]kyber.Scalar, d_1, d_2 int) {
// 	// Print the univariate polynomials
// 	for j := 0; j < len(f_x); j++ {
// 		fmt.Printf("f_%d(X) = [", j)
// 		for i := 0; i < len(f_x[0]); i++ {
// 			if i > 0 {
// 				fmt.Printf("%sX^%d ", f_x[j][i].String(), i)
// 			} else {
// 				fmt.Printf("%s ", f_x[j][i].String())
// 			}
// 		}
// 		fmt.Println("]")
// 	}
// }

func BingoReconstruct(verifiers []Verifier, ver int, set *kzg.KzgShareSetup, k int, d_2 int, cm []kyber.Point) kyber.Scalar {
	//line 1: shares_i_k = null set
	shares := make([]kzg.Proof, d_2+2)
	shares_l := make([]kyber.Scalar, d_2+2)

	n := 0
	i := 0
	for checkForNotNil(shares) < d_2+2 {
		neg_k := set.ReturnSuite().G1().Scalar().Neg(set.ReturnSuite().G1().Scalar().SetInt64(int64(k)))
		p, a_i, a_j_i, _ := kzg.KZGEval(set, verifiers[i].polynomial.Coefficients(), verifiers[i].polynomial.Coefficients_2(), neg_k)

		if kzg.KZGVerify(set, cm, i, p, neg_k, a_i, a_j_i) {
			shares[n] = *kzg.NewProof(i, p, a_i, a_j_i, nil)
			shares_l[n] = a_i
			n++
		}
		i++
	}

	zero := set.ReturnSuite().G1().Scalar().SetInt64(int64(0))
	v_k := poly.LagrangeInterpolation(set.ReturnSuite(), shares_l, zero)

	return v_k

}
