package modules

import (
	"fmt"
	"strings"

	"github.com/playwright-community/playwright-go"

	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/detection"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/utils"
)

// buildGetURL merges all GET parameters from a group onto an endpoint.
func buildGetURL(baseURL string, params []*models.Parameter) string {
	names := make([]string, 0, len(params))
	values := make([]string, 0, len(params))
	for _, p := range params {
		names = append(names, p.ParamName)
		values = append(values, p.ParamValue)
	}
	return utils.BuildGetURL(baseURL, names, values)
}

// buildPostData renders a urlencoded body for a parameter group.
func buildPostData(params []*models.Parameter) string {
	pairs := make([]utils.KV, 0, len(params))
	for _, p := range params {
		pairs = append(pairs, utils.KV{Key: p.ParamName, Value: p.ParamValue})
	}
	return utils.BuildQueryOrdered(pairs)
}

func probeGetMatrix(sess *browser.Session, endpoint string, reflectedParams []*models.Parameter,
	log *logger.Logger, waf *detection.WAFManager, cfg *models.ScanConfig) {

	tokens := map[string]string{}
	for _, p := range reflectedParams {
		tokens[p.ParamName] = "m" + utils.RandomString(4)
	}

	matrixParams := make([]*models.Parameter, 0, len(reflectedParams))
	for _, p := range reflectedParams {
		mp := models.NewParameter()
		mp.ParamName = p.ParamName
		mp.ParamValue = detection.BuildMatrixProbe(tokens[p.ParamName])
		mp.Location = p.Location
		mp.ActionURL = p.ActionURL
		matrixParams = append(matrixParams, mp)
	}
	matrixURL := buildGetURL(endpoint, matrixParams)

	resp, err := sess.Goto(matrixURL)
	if err != nil {
		if log != nil {
			log.Debug(fmt.Sprintf("GET matrix probe failed on %s: %s", endpoint, utils.CleanErrorText(err.Error())))
		}
		return
	}
	sess.WaitForTimeout(1000)

	raw := ""
	if resp != nil {
		if body, terr := resp.Text(); terr == nil {
			raw = body
		}
	}
	dom, _ := sess.OuterHTML()
	combined := raw + "\n" + dom

	if waf != nil && resp != nil && cfg != nil {
		headers, _ := resp.AllHeaders()
		waf.HandleResponse(resp.Status(), headers, combined, cfg)
	}

	for _, p := range reflectedParams {
		if token, ok := tokens[p.ParamName]; ok {
			p.CharMatrix = detection.AnalyzeCharacterMatrix(combined, token)
			if log != nil {
				log.CharMatrix(p.ParamName, p.CharMatrix)
			}
		}
	}
}

func probePostMatrix(sess *browser.Session, endpoint string, postParams []*models.Parameter,
	reflectedParams []*models.Parameter, formIndex int, log *logger.Logger,
	waf *detection.WAFManager, cfg *models.ScanConfig) {

	tokens := map[string]string{}
	for _, p := range reflectedParams {
		tokens[p.ParamName] = "m" + utils.RandomString(4)
	}

	payloadParams := make([]map[string]string, 0, len(postParams))
	for _, p := range postParams {
		val := p.ParamValue
		if token, ok := tokens[p.ParamName]; ok {
			val = detection.BuildMatrixProbe(token)
		}
		payloadParams = append(payloadParams, map[string]string{"param_name": p.ParamName, "param_value": val})
	}

	var navResp playwright.Response

	if formIndex != -1 {
		_, err := sess.Eval(`({ formIndex, params }) => {
			const form = document.querySelectorAll('form')[formIndex];
			for (const p of params) {
				let input = form.querySelector(`+"`[name=\"${p.param_name}\"]`"+`);
				if (!input) {
					input = document.createElement('input');
					input.name = p.param_name;
					form.appendChild(input);
				}
				input.value = p.param_value;
			}
		}`, map[string]interface{}{"formIndex": formIndex, "params": payloadParams})
		if err != nil && log != nil {
			log.Debug(fmt.Sprintf("POST matrix form fill failed on %s: %s", endpoint, utils.CleanErrorText(err.Error())))
		}

		navResp, _ = sess.SubmitAndWait(`(formIndex) => {
			document.querySelectorAll('form')[formIndex].requestSubmit();
		}`, formIndex)
	} else {
		navResp, _ = sess.SubmitAndWait(`({ action, params }) => {
			const form = document.createElement('form');
			form.method = 'POST';
			form.action = action;
			for (const p of params) {
				const input = document.createElement('input');
				input.type = 'hidden';
				input.name = p.param_name;
				input.value = p.param_value;
				form.appendChild(input);
			}
			document.body.appendChild(form);
			form.submit();
		}`, map[string]interface{}{"action": endpoint, "params": payloadParams})
	}

	if waf != nil && navResp != nil && cfg != nil {
		headers, _ := navResp.AllHeaders()
		body, _ := sess.Content()
		waf.HandleResponse(navResp.Status(), headers, body, cfg)
	}

	sess.WaitForTimeout(1000)
	html, _ := sess.Content()
	for _, p := range reflectedParams {
		if token, ok := tokens[p.ParamName]; ok {
			p.CharMatrix = detection.AnalyzeCharacterMatrix(html, token)
			if log != nil {
				log.CharMatrix(p.ParamName, p.CharMatrix)
			}
		}
	}
}

func probeDOMMatrix(sess *browser.Session, endpoint string, domParam *models.Parameter,
	log *logger.Logger, waf *detection.WAFManager, cfg *models.ScanConfig) {

	token := "m" + utils.RandomString(4)
	mParam := models.NewParameter()
	mParam.ParamName = domParam.ParamName
	mParam.ParamValue = detection.BuildMatrixProbe(token)
	mParam.Location = "DOM"
	mParam.ActionURL = endpoint

	mURL := buildGetURL(endpoint, []*models.Parameter{mParam})
	resp, err := sess.Goto(mURL)
	if err != nil {
		if log != nil {
			log.Debug(fmt.Sprintf("DOM matrix probe failed: %s", utils.CleanErrorText(err.Error())))
		}
		return
	}
	sess.WaitForTimeout(1000)
	dom, _ := sess.OuterHTML()

	if waf != nil && resp != nil && cfg != nil {
		headers, _ := resp.AllHeaders()
		waf.HandleResponse(resp.Status(), headers, dom, cfg)
	}

	domParam.CharMatrix = detection.AnalyzeCharacterMatrix(dom, token)
	if log != nil {
		log.CharMatrix(domParam.ParamName, domParam.CharMatrix)
	}
}

// RunReflectionEngine performs Step 1: reflection/context analysis and matrix probing.
func RunReflectionEngine(sess *browser.Session, parameters []*models.Parameter, log *logger.Logger,
	waf *detection.WAFManager, cfg *models.ScanConfig) []*models.Parameter {

	if log != nil {
		log.Action(fmt.Sprintf("analyzing reflection and injection contexts for %d parameter(s)...", len(parameters)))
	}
	if len(parameters) == 0 {
		return nil
	}

	sessionID := utils.RandomString(8)
	for idx, p := range parameters {
		p.ParamValue = fmt.Sprintf("%s%d", sessionID, idx)
	}

	// group by action URL, preserving first-seen order
	var order []string
	grouped := map[string][]*models.Parameter{}
	for _, p := range parameters {
		if _, ok := grouped[p.ActionURL]; !ok {
			order = append(order, p.ActionURL)
		}
		grouped[p.ActionURL] = append(grouped[p.ActionURL], p)
	}

	for _, endpoint := range order {
		params := grouped[endpoint]
		var getParams, postParams, domParams []*models.Parameter
		for _, p := range params {
			switch p.Location {
			case "GET":
				getParams = append(getParams, p)
			case "POST":
				postParams = append(postParams, p)
			case "DOM":
				domParams = append(domParams, p)
			}
		}

		if len(getParams) > 0 {
			var manualGet, probeGet []*models.Parameter
			for _, p := range getParams {
				if p.CustomContext != "" {
					manualGet = append(manualGet, p)
				} else {
					probeGet = append(probeGet, p)
				}
			}
			for _, p := range manualGet {
				ref := models.NewReflectionResult()
				ref.ParameterName = p.ParamName
				ref.Reflected = true
				ref.Context = p.CustomContext
				ref.RequestURL = endpoint
				ref.RequestMethod = "GET"
				p.Reflections = append(p.Reflections, ref)
				p.Tested = true
				if log != nil {
					log.Success(fmt.Sprintf("[%s] '%s' set to %s context (manual)", p.Location, p.ParamName, strings.ToUpper(p.CustomContext)))
				}
			}

			if len(probeGet) > 0 {
				probeURL := buildGetURL(endpoint, probeGet)
				if log != nil {
					log.Debug(fmt.Sprintf("probing %d GET param(s) on %s in single request", len(probeGet), endpoint))
				}
				resp, err := sess.Goto(probeURL)
				if err != nil {
					if log != nil {
						log.Debug(fmt.Sprintf("GET probe failed on %s: %s", endpoint, utils.CleanErrorText(err.Error())))
					}
					for _, p := range probeGet {
						if len(p.Reflections) == 0 {
							ref := models.NewReflectionResult()
							ref.ParameterName = p.ParamName
							ref.Reflected = false
							ref.Context = "html"
							ref.RequestURL = endpoint
							ref.RequestMethod = "GET"
							p.Reflections = append(p.Reflections, ref)
							if log != nil {
								log.Neutral(fmt.Sprintf("[%s] '%s' no reflection detected (default: HTML)", p.Location, p.ParamName))
							}
						}
					}
				} else {
					sess.WaitForTimeout(2000)
					html, _ := sess.OuterHTML()
					status := 200
					if resp != nil {
						status = resp.Status()
					}
					if log != nil {
						log.Debug(fmt.Sprintf("GET reflection probe returned HTTP %d (%d chars)", status, len(html)))
					}
					if waf != nil && resp != nil && cfg != nil {
						headers, _ := resp.AllHeaders()
						waf.HandleResponse(status, headers, html, cfg)
					}
					statusText := fmt.Sprintf("HTTP %d", status)

					for _, p := range probeGet {
						reflections := detection.DetectAllReflections(html, p.ParamValue)
						p.Tested = true
						if len(reflections) > 0 {
							for _, r := range reflections {
								ref := models.NewReflectionResult()
								ref.ParameterName = p.ParamName
								ref.Reflected = true
								ref.Context = r.Context
								ref.Tags = r.Tags
								ref.RequestURL = probeURL
								ref.RequestMethod = "GET"
								ref.Text = statusText
								p.Reflections = append(p.Reflections, ref)
								if log != nil {
									tagInfo := ""
									if r.Tags != "" {
										tagInfo = fmt.Sprintf(" (tag: <%s>)", r.Tags)
									}
									log.Success(fmt.Sprintf("[%s] '%s' reflects in %s context%s", p.Location, p.ParamName, strings.ToUpper(r.Context), tagInfo))
									log.Debug(fmt.Sprintf("reflection detected: param='%s' token='%s' context=%s tag=%s", p.ParamName, p.ParamValue, r.Context, r.Tags))
								}
							}
						} else {
							ref := models.NewReflectionResult()
							ref.ParameterName = p.ParamName
							ref.Reflected = false
							ref.Context = "html"
							ref.RequestURL = probeURL
							ref.RequestMethod = "GET"
							ref.Text = statusText
							p.Reflections = append(p.Reflections, ref)
							if log != nil {
								log.Neutral(fmt.Sprintf("[%s] '%s' no reflection detected (default: HTML)", p.Location, p.ParamName))
							}
						}
					}

					var reflectedGet []*models.Parameter
					for _, p := range getParams {
						for _, r := range p.Reflections {
							if r.Reflected {
								reflectedGet = append(reflectedGet, p)
								break
							}
						}
					}
					if len(reflectedGet) > 0 {
						probeGetMatrix(sess, endpoint, reflectedGet, log, waf, cfg)
					}
				}
			}
		}

		if len(postParams) > 0 {
			var manualPost, probePost []*models.Parameter
			for _, p := range postParams {
				if p.CustomContext != "" {
					manualPost = append(manualPost, p)
				} else {
					probePost = append(probePost, p)
				}
			}
			for _, p := range manualPost {
				ref := models.NewReflectionResult()
				ref.ParameterName = p.ParamName
				ref.Reflected = true
				ref.Context = p.CustomContext
				ref.RequestURL = endpoint
				ref.RequestBody = buildPostData(postParams)
				ref.RequestMethod = "POST"
				p.Reflections = append(p.Reflections, ref)
				p.Tested = true
				if log != nil {
					log.Success(fmt.Sprintf("[%s] '%s' set to %s context (manual)", p.Location, p.ParamName, strings.ToUpper(p.CustomContext)))
				}
			}

			if len(probePost) > 0 {
				if log != nil {
					log.Debug(fmt.Sprintf("probing %d POST param(s) on %s...", len(probePost), endpoint))
				}
				statusText := "HTTP 200"
				func() {
					if _, err := sess.Goto(endpoint); err != nil {
						_, _ = sess.Page.Goto("about:blank", playwright.PageGotoOptions{Timeout: playwright.Float(5000)})
					}

					formIndex := -1
					paramNamesArg := make([]map[string]string, 0, len(probePost))
					for _, p := range probePost {
						paramNamesArg = append(paramNamesArg, map[string]string{"param_name": p.ParamName})
					}
					if v, err := sess.Eval(`(params) => {
						const forms = [...document.querySelectorAll('form')];
						for (let i = 0; i < forms.length; i++) {
							for (const p of params) {
								if (forms[i].querySelector(`+"`[name=\"${p.param_name}\"]`"+`)) return i;
							}
						}
						return -1;
					}`, paramNamesArg); err == nil {
						formIndex = toInt(v)
					}

					var navResp playwright.Response
					if formIndex != -1 {
						if log != nil {
							log.Debug(fmt.Sprintf("found POST form at index %d matching parameters", formIndex))
						}
						paramsArg := make([]map[string]string, 0, len(probePost))
						for _, p := range probePost {
							paramsArg = append(paramsArg, map[string]string{"param_name": p.ParamName, "param_value": p.ParamValue})
						}
						_, _ = sess.Eval(`({ formIndex, params }) => {
							const form = document.querySelectorAll('form')[formIndex];
							for (const p of params) {
								let input = form.querySelector(`+"`[name=\"${p.param_name}\"]`"+`);
								if (!input) {
									input = document.createElement('input');
									input.name = p.param_name;
									form.appendChild(input);
								}
								input.value = p.param_value;
							}
						}`, map[string]interface{}{"formIndex": formIndex, "params": paramsArg})

						navResp, _ = sess.SubmitAndWait(`(formIndex) => {
							document.querySelectorAll('form')[formIndex].requestSubmit();
						}`, formIndex)
						if navResp != nil {
							statusText = fmt.Sprintf("HTTP %d", navResp.Status())
						}
					} else {
						if log != nil {
							log.Debug(fmt.Sprintf("no physical HTML form on %s; submitting via synthetic dynamic form", endpoint))
						}
						paramsArg := make([]map[string]string, 0, len(probePost))
						for _, p := range probePost {
							paramsArg = append(paramsArg, map[string]string{"param_name": p.ParamName, "param_value": p.ParamValue})
						}
						navResp, _ = sess.SubmitAndWait(`({ action, params }) => {
							const form = document.createElement('form');
							form.method = 'POST';
							form.action = action;
							for (const p of params) {
								const input = document.createElement('input');
								input.type = 'hidden';
								input.name = p.param_name;
								input.value = p.param_value;
								form.appendChild(input);
							}
							document.body.appendChild(form);
							form.submit();
						}`, map[string]interface{}{"action": endpoint, "params": paramsArg})
						if navResp != nil {
							statusText = fmt.Sprintf("HTTP %d", navResp.Status())
						}
					}

					sess.WaitForTimeout(1000)
					html, _ := sess.Content()
					if log != nil {
						log.Debug(fmt.Sprintf("POST reflection probe returned %s (%d chars)", statusText, len(html)))
					}
					if waf != nil && navResp != nil && cfg != nil {
						headers, _ := navResp.AllHeaders()
						waf.HandleResponse(navResp.Status(), headers, html, cfg)
					}

					for _, p := range probePost {
						reflections := detection.DetectAllReflections(html, p.ParamValue)
						p.Tested = true
						if len(reflections) > 0 {
							for _, r := range reflections {
								ref := models.NewReflectionResult()
								ref.ParameterName = p.ParamName
								ref.Reflected = true
								ref.Context = r.Context
								ref.Tags = r.Tags
								ref.RequestURL = endpoint
								ref.RequestBody = buildPostData(probePost)
								ref.RequestMethod = "POST"
								ref.Text = statusText
								p.Reflections = append(p.Reflections, ref)
								if log != nil {
									tagInfo := ""
									if r.Tags != "" {
										tagInfo = fmt.Sprintf(" (tag: <%s>)", r.Tags)
									}
									log.Success(fmt.Sprintf("[%s] '%s' reflects in %s context%s", p.Location, p.ParamName, strings.ToUpper(r.Context), tagInfo))
									log.Debug(fmt.Sprintf("reflection detected: param='%s' token='%s' context=%s tag=%s", p.ParamName, p.ParamValue, r.Context, r.Tags))
								}
							}
						} else {
							ref := models.NewReflectionResult()
							ref.ParameterName = p.ParamName
							ref.Reflected = false
							ref.Context = "html"
							ref.RequestURL = endpoint
							ref.RequestBody = buildPostData(probePost)
							ref.RequestMethod = "POST"
							ref.Text = statusText
							p.Reflections = append(p.Reflections, ref)
							if log != nil {
								log.Neutral(fmt.Sprintf("[%s] '%s' no reflection detected (default: HTML)", p.Location, p.ParamName))
							}
						}
					}

					var reflectedPost []*models.Parameter
					for _, p := range postParams {
						for _, r := range p.Reflections {
							if r.Reflected {
								reflectedPost = append(reflectedPost, p)
								break
							}
						}
					}
					if len(reflectedPost) > 0 {
						probePostMatrix(sess, endpoint, postParams, reflectedPost, formIndex, log, waf, cfg)
					}
				}()
			}
		}

		for _, domParam := range domParams {
			if domParam.CustomContext != "" {
				ref := models.NewReflectionResult()
				ref.ParameterName = domParam.ParamName
				ref.Reflected = true
				ref.Context = domParam.CustomContext
				ref.RequestURL = endpoint
				ref.RequestMethod = "GET"
				domParam.Reflections = append(domParam.Reflections, ref)
				domParam.Tested = true
				if log != nil {
					log.Success(fmt.Sprintf("[%s] '%s' set to %s context (manual)", domParam.Location, domParam.ParamName, strings.ToUpper(domParam.CustomContext)))
				}
				continue
			}

			probeURL := buildGetURL(endpoint, []*models.Parameter{domParam})
			if log != nil {
				log.Debug(fmt.Sprintf("probing DOM param '%s' on %s...", domParam.ParamName, probeURL))
			}
			resp, err := sess.Goto(probeURL)
			if err != nil {
				if log != nil {
					log.Debug(fmt.Sprintf("DOM probe failed: %s", utils.CleanErrorText(err.Error())))
				}
				ref := models.NewReflectionResult()
				ref.ParameterName = domParam.ParamName
				ref.Reflected = false
				ref.Context = "dom_js_html"
				ref.RequestURL = probeURL
				ref.RequestMethod = "GET"
				domParam.Reflections = append(domParam.Reflections, ref)
				if log != nil {
					log.Neutral(fmt.Sprintf("[%s] '%s' no reflection detected (default: DOM_JS_HTML)", domParam.Location, domParam.ParamName))
				}
				continue
			}

			sess.WaitForTimeout(2000)
			html, _ := sess.OuterHTML()
			status := 200
			if resp != nil {
				status = resp.Status()
			}
			if log != nil {
				log.Debug(fmt.Sprintf("DOM probe returned HTTP %d (%d chars)", status, len(html)))
			}
			if waf != nil && resp != nil && cfg != nil {
				headers, _ := resp.AllHeaders()
				waf.HandleResponse(status, headers, html, cfg)
			}

			reflections := detection.DetectAllReflections(html, domParam.ParamValue)
			domParam.Tested = true
			if len(reflections) > 0 {
				for _, r := range reflections {
					ref := models.NewReflectionResult()
					ref.ParameterName = domParam.ParamName
					ref.Reflected = true
					ref.Context = r.Context
					ref.Tags = r.Tags
					ref.RequestURL = probeURL
					ref.RequestMethod = "GET"
					domParam.Reflections = append(domParam.Reflections, ref)
					if log != nil {
						tagInfo := ""
						if r.Tags != "" {
							tagInfo = fmt.Sprintf(" (tag: <%s>)", r.Tags)
						}
						log.Success(fmt.Sprintf("[%s] '%s' reflects in %s context%s", domParam.Location, domParam.ParamName, strings.ToUpper(r.Context), tagInfo))
					}
				}
				probeDOMMatrix(sess, endpoint, domParam, log, waf, cfg)
			} else {
				ref := models.NewReflectionResult()
				ref.ParameterName = domParam.ParamName
				ref.Reflected = false
				ref.Context = "dom_js_html"
				ref.RequestURL = probeURL
				ref.RequestMethod = "GET"
				domParam.Reflections = append(domParam.Reflections, ref)
				if log != nil {
					log.Neutral(fmt.Sprintf("[%s] '%s' no reflection detected (default: DOM_JS_HTML)", domParam.Location, domParam.ParamName))
				}
			}
		}
	}

	return parameters
}
