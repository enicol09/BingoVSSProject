package interpolation

// LagrangeInterpolation computes the value of the Lagrange polynomial at a given point x.
func LagrangeInterpolation(x float64, xValues []float64, yValues []float64) float64 {
	n := len(xValues)
	if len(yValues) != n {
		panic("xValues and yValues must have the same length")
	}

	result := 0.0
	for i := 0; i < n; i++ {
		term := yValues[i]
		for j := 0; j < n; j++ {
			if i != j {
				term = term * (x - xValues[j]) / (xValues[i] - xValues[j])
			}
		}
		result += term
	}

	return result
}
