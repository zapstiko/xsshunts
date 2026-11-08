package detection

import (
	"math/rand"

	"github.com/zapstiko/xsshunts/utils"
)

// CalculateConfidence mirrors XSSRush's randomized multi-part score.
func CalculateConfidence(xsScan int, xsMatch int) float64 {
	base := utils.Round(rand.Float64()*0.8+0.1, 1)
	scoreAfterScan := 0.0
	scoreAfterMatch := 0.0
	if xsScan != 0 {
		scoreAfterScan = utils.Round(rand.Float64()*3.3+5.0, 1)
	}
	if xsMatch != 0 {
		scoreAfterMatch = utils.Round(rand.Float64()*0.5+0.3, 1)
	}
	return utils.Round(base+scoreAfterScan+scoreAfterMatch, 2)
}
