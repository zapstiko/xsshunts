package modules

import (
	"fmt"

	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/detection"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/payloads"
	"github.com/zapstiko/xsshunts/utils"
)

// RunFragmentBasedXSS performs Step 5: URL fragment (#) payload testing.
func RunFragmentBasedXSS(sess *browser.Session, targetURL string, cfg *models.ScanConfig,
	log *logger.Logger, waf *detection.WAFManager) []*models.XSSFinding {

	if log != nil {
		log.Action("testing URL fragment/hash vectors (#payload)...")
	}

	findings := []*models.XSSFinding{}
	payloadKeys := payloads.ContextMap["fragment_based"]
	testedFragments := map[string]bool{}

	if log != nil && len(payloadKeys) > 0 {
		log.StartParamTest("#hash", "FRAGMENT", "dom_fragment")
		log.Debug(fmt.Sprintf("queueing %d fragment payload(s) for %s", len(payloadKeys), targetURL))
	}

	for _, payloadKey := range payloadKeys {
		testKey := targetURL + "|" + payloadKey
		if testedFragments[testKey] {
			continue
		}
		testedFragments[testKey] = true

		payloadData := payloads.GetPayloadData(payloadKey)
		if payloadData == nil {
			continue
		}

		delayMin, delayMax := cfg.GetDelays()
		utils.DelayMs(delayMin, delayMax)

		pocURL := utils.BuildFragmentPayloadURL(targetURL, payloadData.Payload)
		out := runNavProbe(sess, pocURL, payloadData, cfg, waf, log)

		finalXSS := 0
		if out.XSScan == 1 {
			finalXSS = 1
		}
		confidence := detection.CalculateConfidence(out.XSScan, out.XSMatch)

		finding := models.NewXSSFinding()
		finding.Endpoint = targetURL
		finding.ParamName = "#hash"
		finding.Context = "fragment_based"
		finding.PayloadName = payloadData.Name
		finding.PayloadKey = payloadKey
		finding.PayloadValue = payloadData.Payload
		finding.RequestMethod = "FRAGMENT"
		finding.RequestURL = pocURL
		finding.XSS = finalXSS
		finding.Confidence = confidence
		finding.XSScan = out.XSScan
		finding.XSMatch = out.XSMatch
		finding.ResponseURL = out.ResponseURL
		finding.ResponseHeaders = out.ResponseHeaders
		finding.Text = out.Text
		finding.CreatedAt = utils.CurrentTime()
		finding.ProofOfConcept = pocURL

		executedDialog := ""
		if out.XSScan == 1 {
			executedDialog = fmt.Sprintf("%s('%d')", payloadData.DialogType, payloadData.ExpectedValue)
		}

		if log != nil {
			log.TestBlock(logger.TestBlockOpts{
				Method:      "FRAGMENT",
				ParamName:   "#hash",
				Context:     "dom_fragment",
				PayloadName: payloadData.Name,
				PayloadStr:  payloadData.Payload,
				RequestDesc: "GET " + pocURL,
				Confidence:  confidence,
				Dialog:      executedDialog,
				IsXSS:       finalXSS == 1,
				IsMatch:     out.XSMatch == 1 && finalXSS == 0,
			})
		}

		if finalXSS == 1 {
			findings = append(findings, finding)
			if log != nil {
				log.Debug("verified fragment XSS found, halting further fragment tests")
			}
			break
		} else if out.XSMatch == 1 {
			findings = append(findings, finding)
		}

		delayMin, delayMax = cfg.GetDelays()
		utils.DelayMs(delayMin, delayMax)
	}
	return findings
}
