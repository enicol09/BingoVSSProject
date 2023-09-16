# Vandemonde Matrix and Lagrange Interpolation Implementation

This repository provides implementations for both the Vandemonde Matrix for scalars and Lagrange interpolation. Below is a detailed explanation of both concepts.

## Table of Contents

- [Vandemonde Matrix](#vandemonde-matrix)
- [Lagrange Interpolation](#lagrange-interpolation)


## Vandemonde Matrix

A Vandemonde matrix is a matrix with the terms of a geometric progression in each row. It's commonly used in polynomial interpolation. Given a sequence of \( n \) numbers \( x_1, x_2, ..., x_n \), the Vandemonde matrix \( V \) is defined as:

\[
V = \begin{bmatrix}
1 & x_1 & x_1^2 & \dots & x_1^{n-1} \\
1 & x_2 & x_2^2 & \dots & x_2^{n-1} \\
\vdots & \vdots & \vdots & \ddots & \vdots \\
1 & x_n & x_n^2 & \dots & x_n^{n-1} \\
\end{bmatrix}
\]

### Properties

- The determinant of a square Vandemonde matrix can be expressed as the product of the differences between its columns.
- Vandemonde matrices are generally ill-conditioned, which means that they can be numerically unstable in certain computations.

## Lagrange Interpolation

Lagrange interpolation is a method to find a polynomial that fits a given set of points. Given \( n \) points \( (x_1, y_1), (x_2, y_2), ..., (x_n, y_n) \), the Lagrange polynomial \( L(x) \) is defined as:

\[
L(x) = \sum_{i=1}^{n} y_i \cdot l_i(x)
\]

where \( l_i(x) \) is the Lagrange basis polynomial:

\[
l_i(x) = \prod_{j=1, j \neq i}^{n} \frac{x - x_j}{x_i - x_j}
\]

### Properties

- The Lagrange polynomial is unique for a given set of points.
- It's an exact interpolation method, meaning the polynomial will pass through all given points.
