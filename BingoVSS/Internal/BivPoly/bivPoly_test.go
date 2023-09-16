package bivpoly

import (
	"testing"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/stretchr/testify/require"
)

func TestCreationOfBivariate(test *testing.T) {
	g := bn256.NewSuite()
	rand := g.RandomStream()
	d_1 := 4 //degree in x
	d_2 := 2 //degree in y

	poly := NewBivPolyRandom(g, d_1, d_2, rand)
	require.Len(test, poly.coeffs, d_1)
}

func TestCreationSharingRandom(test *testing.T) {

	g := bn256.NewSuite()
	rand := g.RandomStream()
	d_1 := 4 //degree in x
	d_2 := 2 //degree in y

	poly := NewBivPolyRandom(g, d_1+1, d_2+1, rand)
	require.Len(test, poly.coeffs, d_1+1)

	//requires creation of secrets in scalar mode (sk>f)

	m := 4

	secrets := make([]kyber.Scalar, m+1)

	for i := 0; i <= m; i++ {
		secrets[i] = g.G1().Scalar().Pick(g.RandomStream())
	}

	poly_s := NewPrivBivPoly(g, poly, d_1, d_2, secrets)

	require.Len(test, poly_s.coeffs, d_1+1)

}

func TestReconstructionOfSecretsRandom(test *testing.T) {

	g := bn256.NewSuite()
	rand := g.RandomStream()
	d_1 := 4 //degree in x
	d_2 := 2 //degree in y

	poly := NewBivPolyRandom(g, d_1+1, d_2+1, rand)

	m := 4

	secrets := make([]kyber.Scalar, m+1)

	for i := 0; i <= m; i++ {
		secrets[i] = g.G1().Scalar().Pick(g.RandomStream())
	}

	poly_s := NewPrivBivPoly(g, poly, d_1+1, d_2+1, secrets)

	f_p := CreateProjectionPolynomials(g, poly_s.coeffs, d_1+1, d_2+1, d_2+1)

	// //Create the shares for each
	shares := make([][]kyber.Scalar, len(f_p))
	for i := 0; i < len(f_p); i++ {
		shares[i] = make([]kyber.Scalar, len(secrets))

		shares[i] = findNegShares(f_p[i], len(secrets), g)
	}

	// We need to reconstruct the polynomials for each shares
	for i := 0; i < len(secrets); i++ { //for each k
		//trying to reconstruct secret_i
		poly_sk := make([]kyber.Scalar, len(shares))
		for j := 0; j < len(shares); j++ {
			poly_sk[j] = shares[j][i]
		}

		//reconstruct the polynomial
		poly_rec := RecoverVandermondePos(g, poly_sk, len(shares))
		// evaluate it at 0
		x := g.G1().Scalar().SetInt64(0)
		reco := EvaluatePolynomial(poly_rec, x, g)

		require.True(test, reco.Equal(secrets[i]))

	}
}

func TestReconstructionOfSecretsRandomLangrange(test *testing.T) {

	g := bn256.NewSuite()
	rand := g.RandomStream()
	d_1 := 4 //degree in x
	d_2 := 2 //degree in y

	poly := NewBivPolyRandom(g, d_1+1, d_2+1, rand)

	//requires creation of secrets in scalar mode (sk>f)
	m := 4

	secrets := make([]kyber.Scalar, m+1)

	for i := 0; i <= m; i++ {
		secrets[i] = g.G1().Scalar().Pick(g.RandomStream())
	}

	poly_s := NewPrivBivPoly(g, poly, d_1+1, d_2+1, secrets)

	//we are creating again the univariate polynomials

	f_p := CreateProjectionPolynomials(g, poly_s.coeffs, d_1+1, d_2+1, d_2+1)

	// //Create the shares for each
	shares := make([][]kyber.Scalar, len(f_p))
	for i := 0; i < len(f_p); i++ {
		shares[i] = make([]kyber.Scalar, len(secrets))

		shares[i] = findNegShares(f_p[i], len(secrets), g)
	}

	// We need to reconstruct the polynomials for each shares
	for i := 0; i < len(secrets); i++ { //for each k
		//trying to reconstruct secret_i
		poly_sk := make([]kyber.Scalar, len(shares))
		for j := 0; j < len(shares); j++ {
			poly_sk[j] = shares[j][i]
		}

		x := g.G1().Scalar().SetInt64(0)

		reco := LagrangeInterpolation(g, poly_sk, x)

		require.True(test, reco.Equal(secrets[i]))

	}
}
