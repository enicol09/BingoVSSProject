This is an implementation of KZG Commitments based on this wonderful blog:

https://alinush.github.io/2020/05/06/kzg-polynomial-commitments.html#evaluation-proofs

A lot of inspiration about the implementation is due to this github: 
https://github.com/arnaucube/kzg-commitments-study

This is the simplest form without batching proofs and utilises: bn256 by drand/kyber.

Small explanation of KZGs:
--------------------------

## Trusted Setup

Trusted setup is a crucial part of cryptographic protocols. It involves the generation of public parameters that are used in the system. Below, you'll find details about the commitment, evaluation proofs, and verification of an evaluation proof.

### Commitment to Polynomials

To commit to degree \( \leq \ell \) polynomials, you need \(\ell\)-SDH public parameters:

\[ (g,g\tau,g\tau^2,\ldots,g\tau^\ell)=(g\tau^i)_{i\in[0,\ell]} \]

Here, \( \tau \) is called the trapdoor. These parameters should be generated via a distributed protocol[^2^][^3^][^4^] that outputs just the \( g\tau^i \)'s and forgets the trapdoor \( \tau \).

### Commitments

Commitment to \( \phi(X)=\sum_{i\in[0,d]}\phi_iX^i \) is \( c=g\phi(\tau) \) computed as:

\[ c=\prod_{i\in[0,\deg\phi]}(g\tau^i)^{\phi_i}(1) \]

Since it is just one group element, the commitment is constant-sized.

### Evaluation Proofs

To prove an evaluation \( \phi(a)=y \), a quotient polynomial is computed in \( O(d) \) time:

\[ q(X)=\phi(X)-yX-a(2) \]

Then, the constant-sized evaluation proof is:

\[ \pi=gq(\tau)(3) \]

Note that this leverages the polynomial remainder theorem. !!!!!!!!!

### Verifying an Evaluation Proof

A verifier who has the commitment \( c=g\phi(\tau) \), the evaluation \( y=\phi(a) \), and the proof \( \pi=gq(\tau) \) can verify the evaluation in constant time using two pairings:

\[
\begin{align*}
e(c/g^y,g)e(g\phi(\tau)-y,g)e(g,g)\phi(\tau)-y\phi(\tau)-y &= e(\pi,g\tau/g^a) \Leftrightarrow \\
&= e(gq(\tau),g\tau-a) \Leftrightarrow \\
&= e(g,g)q(\tau)(\tau-a) = q(\tau)(\tau-a)(4)(5)(6)(7)
\end{align*}
\]

This effectively checks that \( q(X)=\phi(X)-yX-a \) by checking this equality holds for \( X=\tau \). In other words, it checks that the polynomial remainder theorem holds at \( X=\tau \).

---

[^1^]: https://math.libretexts.org/Bookshelves/Precalculus/Book%3A_Precalculus__An_Investigation_of_Functions_(Lippman_and_Rasmussen)/03%3A_Polynomial_and_Rational_Functions/304%3A_Factor_Theorem_and_Remainder_Theorem
[^2^]: https://scroll.io/blog/kzg
[^3^]: https://alinush.github.io/2020/05/06/kzg-polynomial-commitments.html#evaluation-proofs
[^4^]: https://github.com/arnaucube/kzg-commitments-study


