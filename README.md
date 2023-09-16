# BingoDKG

Since the release of the Pedersen DKG, there have been many advancements in the [DKG]{https://en.wikipedia.org/wiki/Distributed_key_generation} field in the last decade. This is a final project for MSc Information Security at University College London for an exploration of DKG, in collaboration with Drand. The goal is to investigate the current literature regarding DKGs and select candidates that might be suitable for a furhter implementation.

This code is fully experimental and based on research, therefore should not be used in production. 

This current repository is implementing the Verifiable Secret sharing scheme of one of the latest published literature in the field namely, Bingo presented in the paper: https://eprint.iacr.org/2022/1759.

More specifically this repository is based: 
-------------------------------------------
Implements Bingo algorithm using an adjusted PCS of KZG commitments presented by Kate et al. https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf with bivariate polynomial.s

At the current state, the implementation implements correctly the Packed Verifiable Secret Sharing: Bingo. We anticipate in the future for further implementation of the ADKG.

Components implemented:
-----------------------
- BivariatePolynomials (Bingo -> Internal -> BivPoly)
- Interpolation Methods (Bingo -> Internal -> Interpolation)
- KZG Commitments (Simple, 2 Polynomial, Bivariate Scheme)
      Useful links for KZG commitments:
        <br>  -> https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf   <br> 
        <br>  -> https://medium.com/@VitalikButerin/exploring-elliptic-curve-pairings-c73c1864e627   <br> 
        <br>  -> https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html   <br> 
        <br>  -> https://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf  <br> 
        <br>  -> https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/ <br> 
        <br>  -> https://github.com/ethereum/py_pairing/blob/master/py_ecc/bn128/bn128_field_elements.py <br> 

 The TO-DO list:
  -------------------
  - [x] Research and Background Study (presented in the thesis)
  - [x] Implementing BingoDeal
  - [x] Implementing simple PCS for bivariate polynomials 
  - [X] Implementing KZG
  - [x] Implementing BingoShare algorithm
  - [X] Implementing BingoReconstruct
  - [X] Testing (timing and performance benchmarking)
  - [X] Demostration of BingoVSS

Challenges:
-----------
- Hardness of cryptography
- Mathematical Background

Future List:
------------
- Roots of unity
- Batch proofs
- VABA
- ADKG

  
