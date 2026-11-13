package modules

import (
	"fmt"
	"strings"

	"github.com/playwright-community/playwright-go"

	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/detection"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/payloads"
	"github.com/zapstiko/xsshunts/utils"
)

// RunPostBasedXSS performs Step 3: POST form submission payload testing.
func RunPostBasedXSS(sess *browser.Session, parameters []*models.Parameter, cfg *models.ScanConfig,
	log *logger.Logger, waf *detection.WAFManager) []*models.XSSFinding {

	var postParams []*models.Parameter
	for _, p := range parameters {
		if p.Location == "POST" {
			postParams = append(postParams, p)
		}
	}
	if len(postParams) == 0 {
		return nil
	}

	if log != nil {
		log.Action("testing POST-based form injection points...")
	}

	findings := []*models.XSSFinding{}
	testedPayloads := map[string]bool{}
	testedParams := map[string]bool{}

	var order []string
	grouped := map[string][]*models.Parameter{}
	for _, p := range postParams {
		if _, ok := grouped[p.ActionURL]; !ok {
			order = append(order, p.ActionURL)
		}
		grouped[p.ActionURL] = append(grouped[p.ActionURL], p)
	}

	for _, endpoint := range order {
		params := grouped[endpoint]
		for _, param := range params {
			paramKey := strings.ToLower(endpoint) + "|" + strings.ToLower(param.ParamName)
			if testedParams[paramKey] {
				continue
			}
			testedParams[paramKey] = true

			contextName := "html"
			if param.CustomContext != "" {
				contextName = param.CustomContext
			} else if len(param.Reflections) > 0 {
				var reflectedCtx []string
				for _, r := range param.Reflections {
					if r.Reflected && r.Context != "unknown" {
						reflectedCtx = append(reflectedCtx, r.Context)
					}
				}
				if len(reflectedCtx) > 0 {
					contextName = detection.ResolveContextName(reflectedCtx[0], param.Location)
				}
			}

			payloadKeys := detection.GetPayloadKeysForContext(contextName)
			if len(payloadKeys) == 0 {
				continue
			}

			if log != nil {
				log.StartParamTest(param.ParamName, "POST", contextName)
				log.Debug(fmt.Sprintf("queueing %d payload(s) for POST param '%s' on %s", len(payloadKeys), param.ParamName, endpoint))
			}

			for _, payloadKey := range payloadKeys {
				testKey := strings.ToLower(endpoint) + "|" + strings.ToLower(param.ParamName) + "|" + payloadKey
				if testedPayloads[testKey] {
					continue
				}
				testedPayloads[testKey] = true

				payloadData := payloads.GetPayloadData(payloadKey)
				if payloadData == nil {
					continue
				}

				if log != nil {
					log.Trying(payloadData.Name, payloadData.Payload)
				}

				delayMin, delayMax := cfg.GetDelays()
				utils.DelayMs(delayMin, delayMax)

				requestBody := utils.BuildPayloadedBody(params, param.ParamName, payloadData.Payload)

				xsScan := 0
				xsMatch := 0
				text := ""
				responseURL := ""
				var responseHeaders map[string]string

				sess.ExpectDialog(payloadData.DialogType, payloadData.ExpectedValue)

				func() {
					defer sess.ClearDialog()

					if _, err := sess.Goto(endpoint); err != nil {
						_, _ = sess.Page.Goto("about:blank", playwright.PageGotoOptions{Timeout: playwright.Float(5000)})
					}

					formIndex := -1
					if v, err := sess.Eval(`(targetName) => {
						const forms = [...document.querySelectorAll('form')];
						for (let i = 0; i < forms.length; i++) {
							if (forms[i].querySelector(`+"`[name=\"${targetName}\"]`"+`)) return i;
						}
						return -1;
					}`, param.ParamName); err == nil {
						formIndex = toInt(v)
					}

					paramsArg := make([]map[string]string, 0, len(params))
					for _, p := range params {
						paramsArg = append(paramsArg, map[string]string{"param_name": p.ParamName, "param_value": p.ParamValue})
					}

					var navResp playwright.Response
					if formIndex != -1 {
						if log != nil {
							log.Debug(fmt.Sprintf("submitting form index %d with '%s' payload '%s'", formIndex, param.ParamName, payloadData.Name))
						}
						_, _ = sess.Eval(`({ formIndex, params, targetName, payload }) => {
							const form = document.querySelectorAll('form')[formIndex];
							for (const p of params) {
								let input = form.querySelector(`+"`[name=\"${p.param_name}\"]`"+`);
								if (!input) {
									input = document.createElement('input');
									input.name = p.param_name;
									form.appendChild(input);
								}
								if (p.param_name === targetName) {
									input.value = payload;
								} else {
									input.value = p.param_value || '';
								}
							}
						}`, map[string]interface{}{"formIndex": formIndex, "params": paramsArg, "targetName": param.ParamName, "payload": payloadData.Payload})

						navResp, _ = sess.SubmitAndWait(`(formIndex) => {
							document.querySelectorAll('form')[formIndex].requestSubmit();
						}`, formIndex)
						if navResp != nil {
							responseHeaders, _ = navResp.AllHeaders()
							text = fmt.Sprintf("HTTP %d %s", navResp.Status(), navResp.StatusText())
						}
					} else {
						if log != nil {
							log.Debug(fmt.Sprintf("no physical form on %s; submitting payload '%s' via synthetic dynamic form", endpoint, payloadData.Name))
						}
						navResp, _ = sess.SubmitAndWait(`({ action, params, targetName, payload }) => {
							const form = document.createElement('form');
							form.method = 'POST';
							form.action = action;
							for (const p of params) {
								const input = document.createElement('input');
								input.type = 'hidden';
								input.name = p.param_name;
								input.value = (p.param_name === targetName) ? payload : (p.param_value || '');
								form.appendChild(input);
							}
							document.body.appendChild(form);
							form.submit();
						}`, map[string]interface{}{"action": endpoint, "params": paramsArg, "targetName": param.ParamName, "payload": payloadData.Payload})
						if navResp != nil {
							responseHeaders, _ = navResp.AllHeaders()
							text = fmt.Sprintf("HTTP %d %s", navResp.Status(), navResp.StatusText())
						}
					}

					sess.WaitNetworkIdle(3000)
					responseURL = sess.PageURL()
					renderedHTML, _ := sess.Content()

					if log != nil {
						log.Debug(fmt.Sprintf("POST execution returned (%d chars)", len(renderedHTML)))
					}

					if waf != nil {
						statusCode := 200
						if navResp != nil {
							statusCode = navResp.Status()
						}
						waf.HandleResponse(statusCode, responseHeaders, renderedHTML, cfg)
					}

					if sess.DialogMatched() {
						xsScan = 1
					}
					if xsScan == 0 && payloadData.CheckForMatchEnabled() && utils.DetectMatch(renderedHTML, payloadData) {
						xsMatch = 1
						if log != nil {
							log.Debug(fmt.Sprintf("DOM match confirmed in POST response for payload '%s'", payloadData.Name))
						}
					}
				}()

				finalXSS := 0
				if xsScan == 1 {
					finalXSS = 1
				}
				confidence := detection.CalculateConfidence(xsScan, xsMatch)

				formDict := map[string]string{}
				var orderNames []string
				for _, p := range params {
					formDict[p.ParamName] = p.ParamValue
					orderNames = append(orderNames, p.ParamName)
				}
				formDict[param.ParamName] = payloadData.Payload
				pocData := utils.GeneratePostBasedPOC(endpoint, formDict, orderNames)

				finding := models.NewXSSFinding()
				finding.Endpoint = endpoint
				finding.ParamName = param.ParamName
				finding.Context = contextName
				finding.PayloadName = payloadData.Name
				finding.PayloadKey = payloadKey
				finding.PayloadValue = payloadData.Payload
				finding.RequestMethod = "POST"
				finding.RequestURL = endpoint
				finding.RequestBody = requestBody
				finding.XSS = finalXSS
				finding.Confidence = confidence
				finding.XSScan = xsScan
				finding.XSMatch = xsMatch
				finding.ResponseURL = responseURL
				finding.ResponseHeaders = responseHeaders
				finding.Text = text
				finding.CreatedAt = utils.CurrentTime()
				finding.ProofOfConcept = pocData

				executedDialog := ""
				if xsScan == 1 {
					executedDialog = fmt.Sprintf("%s('%d')", payloadData.DialogType, payloadData.ExpectedValue)
				}

				if log != nil {
					log.TestBlock(logger.TestBlockOpts{
						Method:      "POST",
						ParamName:   param.ParamName,
						Context:     contextName,
						PayloadName: payloadData.Name,
						PayloadStr:  payloadData.Payload,
						RequestDesc: "POST " + endpoint,
						Postfields:  requestBody,
						Confidence:  confidence,
						Dialog:      executedDialog,
						IsXSS:       finalXSS == 1,
						IsMatch:     xsMatch == 1 && finalXSS == 0,
					})
				}

				if finalXSS == 1 {
					findings = append(findings, finding)
					if log != nil {
						log.Debug(fmt.Sprintf("verified XSS found for POST param '%s', halting further tests for this param", param.ParamName))
					}
					break
				} else if xsMatch == 1 {
					findings = append(findings, finding)
				}

				delayMin, delayMax = cfg.GetDelays()
				utils.DelayMs(delayMin, delayMax)
			}
		}
	}
	return findings
}
