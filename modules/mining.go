// Package modules implements the 7-step XSS audit pipeline modules.
package modules

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/playwright-community/playwright-go"

	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/config"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/models"
	"github.com/zapstiko/xsshunts/parsers"
	"github.com/zapstiko/xsshunts/utils"
)

var jsReservedWords = map[string]bool{
	"abstract": true, "arguments": true, "await": true, "boolean": true, "break": true, "byte": true,
	"case": true, "catch": true, "char": true, "class": true, "const": true, "continue": true,
	"debugger": true, "default": true, "delete": true, "do": true, "double": true, "else": true,
	"enum": true, "eval": true, "export": true, "extends": true, "false": true, "final": true,
	"finally": true, "float": true, "for": true, "function": true, "goto": true, "if": true,
	"implements": true, "import": true, "in": true, "instanceof": true, "int": true, "interface": true,
	"let": true, "long": true, "native": true, "new": true, "null": true, "package": true,
	"private": true, "protected": true, "public": true, "return": true, "short": true, "static": true,
	"super": true, "switch": true, "synchronized": true, "this": true, "throw": true, "throws": true,
	"transient": true, "true": true, "try": true, "typeof": true, "var": true, "void": true,
	"volatile": true, "while": true, "with": true, "yield": true, "undefined": true, "nan": true,
	"infinity": true,
}

var (
	declVarRegex    = regexp.MustCompile(`\b(?:let|const|var)\s+([^;{\n]+)`)
	assignVarRegex  = regexp.MustCompile(`\bwindow\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=`)
	paramGetRegex   = regexp.MustCompile(`\b(?:get|has|getParameter)\s*\(\s*['"]([a-zA-Z0-9_$-]+)['"]\s*\)`)
	firstIdentRegex = regexp.MustCompile(`^\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`)
)

// extractScriptVariables finds let/const/var identifiers, window assignments and get() params.
func extractScriptVariables(scriptContent string) map[string]bool {
	found := map[string]bool{}
	if strings.TrimSpace(scriptContent) == "" {
		return found
	}

	for _, m := range declVarRegex.FindAllStringSubmatch(scriptContent, -1) {
		clause := m[1]
		for _, part := range strings.Split(clause, ",") {
			idMatch := firstIdentRegex.FindStringSubmatch(part)
			if len(idMatch) < 2 {
				continue
			}
			name := idMatch[1]
			if !jsReservedWords[strings.ToLower(name)] {
				found[name] = true
			}
		}
	}

	for _, m := range assignVarRegex.FindAllStringSubmatch(scriptContent, -1) {
		name := m[1]
		if !jsReservedWords[strings.ToLower(name)] {
			found[name] = true
		}
	}

	for _, m := range paramGetRegex.FindAllStringSubmatch(scriptContent, -1) {
		name := m[1]
		if !jsReservedWords[strings.ToLower(name)] {
			found[name] = true
		}
	}
	return found
}

func generateProbeMap(paramList []string) map[string]string {
	probeMap := map[string]string{}
	used := map[string]bool{}
	for _, p := range paramList {
		for {
			token := utils.RandomString(9)
			if !used[token] {
				used[token] = true
				probeMap[p] = token
				break
			}
		}
	}
	return probeMap
}

func buildProbeURL(endpoint string, paramOrder []string, probeMap map[string]string) string {
	parsed, err := urlParse(endpoint)
	if err != nil {
		return endpoint
	}
	pairs := utils.ParseQueryOrdered(parsed.RawQuery)
	for _, p := range paramOrder {
		token, ok := probeMap[p]
		if !ok {
			continue
		}
		pairs = utils.PatchKeyValue(pairs, p, token)
	}
	parsed.RawQuery = utils.BuildQueryOrdered(pairs)
	return parsed.String()
}

func probeParamReflectionGet(sess *browser.Session, endpoint string, paramList []string, label string, log *logger.Logger) map[string]string {
	if len(paramList) == 0 {
		return map[string]string{}
	}
	probeMap := generateProbeMap(paramList)
	probeURL := buildProbeURL(endpoint, paramList, probeMap)

	html := ""
	if _, err := sess.Goto(probeURL); err == nil {
		if content, err := sess.Content(); err == nil {
			html = content
		}
	} else if resp, err := sess.Ctx.Request().Get(probeURL, playwright.APIRequestContextGetOptions{Timeout: playwright.Float(10000)}); err == nil {
		if body, err := resp.Text(); err == nil {
			html = body
		}
	}

	if html == "" {
		if log != nil {
			log.Debug(fmt.Sprintf("GET %s: probed %d parameter(s) -> no response", label, len(paramList)))
		}
		return map[string]string{}
	}

	reflected := map[string]string{}
	for _, p := range paramList {
		if token, ok := probeMap[p]; ok && strings.Contains(html, token) {
			reflected[p] = token
		}
	}

	if log != nil {
		log.Debug(fmt.Sprintf("GET %s: probed %d parameter(s) -> %d reflected", label, len(paramList), len(reflected)))
	}

	if len(reflected) > 5 || len(reflected) >= int(math.Max(4, float64(len(probeMap))*0.4)) {
		keys := mapKeysInOrder(paramList, reflected)
		keys = utils.ShuffleStrings(keys)
		if len(keys) > 3 {
			keys = keys[:3]
		}
		if log != nil {
			log.Debug(fmt.Sprintf("echo suppression triggered on %s GET (%d reflected) -> downsampled to: %v", label, len(reflected), keys))
		}
		sampled := map[string]string{}
		for _, k := range keys {
			sampled[k] = reflected[k]
		}
		return sampled
	}
	return reflected
}

func probeParamReflectionPost(sess *browser.Session, endpoint string, paramList []string, label string, log *logger.Logger) map[string]string {
	if len(paramList) == 0 {
		return map[string]string{}
	}
	probeMap := generateProbeMap(paramList)
	postURL := stripFragment(endpoint)

	form := map[string]interface{}{}
	for p, token := range probeMap {
		form[p] = token
	}

	resp, err := sess.Ctx.Request().Post(postURL, playwright.APIRequestContextPostOptions{
		Form:    form,
		Timeout: playwright.Float(12000),
	})
	html := ""
	if err == nil {
		if body, terr := resp.Text(); terr == nil {
			html = body
		}
	}

	if html == "" {
		if log != nil {
			log.Debug(fmt.Sprintf("POST %s: probed %d parameter(s) -> no response", label, len(paramList)))
		}
		return map[string]string{}
	}

	reflected := map[string]string{}
	for _, p := range paramList {
		if token, ok := probeMap[p]; ok && strings.Contains(html, token) {
			reflected[p] = token
		}
	}

	if log != nil {
		log.Debug(fmt.Sprintf("POST %s: probed %d parameter(s) -> %d reflected", label, len(paramList), len(reflected)))
	}

	if len(reflected) > 5 || len(reflected) >= int(math.Max(4, float64(len(probeMap))*0.4)) {
		keys := mapKeysInOrder(paramList, reflected)
		keys = utils.ShuffleStrings(keys)
		if len(keys) > 3 {
			keys = keys[:3]
		}
		if log != nil {
			log.Debug(fmt.Sprintf("echo suppression triggered on %s POST (%d reflected) -> downsampled to: %v", label, len(reflected), keys))
		}
		sampled := map[string]string{}
		for _, k := range keys {
			sampled[k] = reflected[k]
		}
		return sampled
	}
	return reflected
}

func probeWordlistReflectionGet(sess *browser.Session, endpoint string, paramList []string, chunkSize int, log *logger.Logger) map[string]string {
	if len(paramList) == 0 {
		return map[string]string{}
	}
	if chunkSize <= 0 {
		chunkSize = 20
	}
	chunks := chunkStrings(paramList, chunkSize)
	if log != nil {
		log.Debug(fmt.Sprintf("probing %d wordlist parameter(s) on GET in %d request(s) (%d params/req)...", len(paramList), len(chunks), chunkSize))
	}

	allReflected := map[string]string{}
	for _, chunk := range chunks {
		probeMap := generateProbeMap(chunk)
		probeURL := buildProbeURL(endpoint, chunk, probeMap)

		html := ""
		if _, err := sess.Goto(probeURL); err == nil {
			if content, err := sess.Content(); err == nil {
				html = content
			}
		} else if resp, err := sess.Ctx.Request().Get(probeURL, playwright.APIRequestContextGetOptions{Timeout: playwright.Float(10000)}); err == nil {
			if body, err := resp.Text(); err == nil {
				html = body
			}
		}
		if html == "" {
			continue
		}
		for _, p := range chunk {
			if token, ok := probeMap[p]; ok && strings.Contains(html, token) {
				allReflected[p] = token
			}
		}
	}

	if log != nil {
		log.Debug(fmt.Sprintf("GET wordlist: probed %d parameter(s) -> %d reflected", len(paramList), len(allReflected)))
	}

	if len(allReflected) > 6 {
		if len(allReflected) >= int(math.Max(6, float64(len(paramList))*0.4)) || len(allReflected) >= 15 {
			keys := mapKeysInOrder(paramList, allReflected)
			keys = utils.ShuffleStrings(keys)
			if len(keys) > 6 {
				keys = keys[:6]
			}
			if log != nil {
				log.Debug(fmt.Sprintf("echo suppression triggered on wordlist GET (%d reflected) -> downsampled to: %v", len(allReflected), keys))
			}
			sampled := map[string]string{}
			for _, k := range keys {
				sampled[k] = allReflected[k]
			}
			return sampled
		}
	}
	return allReflected
}

func probeWordlistReflectionPost(sess *browser.Session, endpoint string, paramList []string, chunkSize int, log *logger.Logger) map[string]string {
	if len(paramList) == 0 {
		return map[string]string{}
	}
	if chunkSize <= 0 {
		chunkSize = 20
	}
	chunks := chunkStrings(paramList, chunkSize)
	if log != nil {
		log.Debug(fmt.Sprintf("probing %d wordlist parameter(s) on POST in %d request(s) (%d params/req)...", len(paramList), len(chunks), chunkSize))
	}

	allReflected := map[string]string{}
	postURL := stripFragment(endpoint)
	for _, chunk := range chunks {
		probeMap := generateProbeMap(chunk)
		form := map[string]interface{}{}
		for p, token := range probeMap {
			form[p] = token
		}
		resp, err := sess.Ctx.Request().Post(postURL, playwright.APIRequestContextPostOptions{
			Form:    form,
			Timeout: playwright.Float(12000),
		})
		html := ""
		if err == nil {
			if body, terr := resp.Text(); terr == nil {
				html = body
			}
		}
		if html == "" {
			continue
		}
		for _, p := range chunk {
			if token, ok := probeMap[p]; ok && strings.Contains(html, token) {
				allReflected[p] = token
			}
		}
	}

	if log != nil {
		log.Debug(fmt.Sprintf("POST wordlist: probed %d parameter(s) -> %d reflected", len(paramList), len(allReflected)))
	}

	if len(allReflected) > 6 {
		if len(allReflected) >= int(math.Max(6, float64(len(paramList))*0.4)) || len(allReflected) >= 15 {
			keys := mapKeysInOrder(paramList, allReflected)
			keys = utils.ShuffleStrings(keys)
			if len(keys) > 6 {
				keys = keys[:6]
			}
			if log != nil {
				log.Debug(fmt.Sprintf("echo suppression triggered on wordlist POST (%d reflected) -> downsampled to: %v", len(allReflected), keys))
			}
			sampled := map[string]string{}
			for _, k := range keys {
				sampled[k] = allReflected[k]
			}
			return sampled
		}
	}
	return allReflected
}

// RunParameterMining performs Step 0: query/form/DOM/wordlist parameter discovery.
func RunParameterMining(sess *browser.Session, targetURL string, customPostfields map[string]string,
	excludeParams []string, wordlistParams []string, log *logger.Logger) []*models.Parameter {

	if log != nil {
		log.Action(fmt.Sprintf("starting parameter discovery on target: %s", targetURL))
	}

	userExcludeSet := map[string]bool{}
	for _, p := range excludeParams {
		userExcludeSet[strings.ToLower(p)] = true
	}
	activeExcludedDOM := append([]string(nil), config.ExcludedVars...)
	for p := range userExcludeSet {
		activeExcludedDOM = append(activeExcludedDOM, p)
	}

	_, _ = sess.Goto(targetURL) // wait_until commit is emulated via default domcontentloaded
	_ = sess.Page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State:   playwright.LoadStateDomcontentloaded,
		Timeout: playwright.Float(4000),
	})
	htmlContent, _ := sess.Content()
	root := utils.ParseHTML(htmlContent)

	parameters := []*models.Parameter{}
	seen := map[string]bool{}

	parsedBase, err := urlParse(targetURL)
	if err != nil {
		return parameters
	}
	originPath := parsedBase.Scheme + "://" + parsedBase.Host + parsedBase.Path
	if !strings.HasSuffix(originPath, "/") && parsedBase.Path == "" {
		originPath += "/"
	}

	queryDict := parsers.ExtractQueryDict(targetURL)
	for name, val := range queryDict {
		if userExcludeSet[strings.ToLower(name)] {
			continue
		}
		key := "GET|" + strings.ToLower(originPath) + "|" + strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		value := val
		if value == "" {
			value = utils.RandomString(9)
		}
		p := models.NewParameter()
		p.ParamName = name
		p.ParamValue = value
		p.ActionURL = originPath
		p.Location = "GET"
		parameters = append(parameters, p)
	}

	forms := utils.CollectForms(root)
	for _, form := range forms {
		method := strings.ToUpper(form.Method)
		if method == "" {
			method = "GET"
		}
		actionURL := parsers.ResolveActionURL(form.Action, targetURL)
		for _, field := range form.Fields {
			name := field.Name
			if name == "" || userExcludeSet[strings.ToLower(name)] {
				continue
			}
			loc := "GET"
			if method == "POST" {
				loc = "POST"
			}
			key := loc + "|" + strings.ToLower(actionURL) + "|" + strings.ToLower(name)
			if seen[key] {
				continue
			}
			seen[key] = true
			value := field.Value
			if value == "" {
				value = utils.RandomString(9)
			}
			p := models.NewParameter()
			p.ParamName = name
			p.ParamValue = value
			p.ActionURL = actionURL
			p.Location = loc
			parameters = append(parameters, p)
		}
	}

	scriptVars := map[string]bool{}
	for _, content := range utils.CollectScriptTexts(root) {
		for v := range extractScriptVariables(content) {
			scriptVars[v] = true
		}
	}
	sortedScriptVars := make([]string, 0, len(scriptVars))
	for v := range scriptVars {
		sortedScriptVars = append(sortedScriptVars, v)
	}
	sort.Strings(sortedScriptVars)
	for _, v := range sortedScriptVars {
		if utils.IsExcludedParam(v, activeExcludedDOM, config.ExcludedVarsRegex) {
			continue
		}
		key := "DOM|" + strings.ToLower(originPath) + "|" + strings.ToLower(v)
		if seen[key] {
			continue
		}
		seen[key] = true
		p := models.NewParameter()
		p.ParamName = v
		p.ParamValue = utils.RandomString(9)
		p.ActionURL = originPath
		p.Location = "DOM"
		parameters = append(parameters, p)
	}

	if windowVars, err := sess.Eval("() => Object.keys(window)"); err == nil {
		if arr, ok := windowVars.([]interface{}); ok {
			var filtered []string
			for _, item := range arr {
				name, ok := item.(string)
				if !ok {
					continue
				}
				if utils.IsExcludedParam(name, activeExcludedDOM, config.ExcludedVarsRegex) || jsReservedWords[strings.ToLower(name)] {
					continue
				}
				filtered = append(filtered, name)
			}
			limit := utils.RandInt(10, 15)
			if limit > len(filtered) {
				limit = len(filtered)
			}
			for _, v := range filtered[:limit] {
				key := "DOM|" + strings.ToLower(originPath) + "|" + strings.ToLower(v)
				if seen[key] {
					continue
				}
				seen[key] = true
				p := models.NewParameter()
				p.ParamName = v
				p.ParamValue = utils.RandomString(9)
				p.ActionURL = originPath
				p.Location = "DOM"
				parameters = append(parameters, p)
			}
			if log != nil {
				log.Debug(fmt.Sprintf("window inspect: sampled %d global properties from %d keys", limit, len(arr)))
			}
		}
	}

	if len(wordlistParams) > 0 {
		var activeWordlist []string
		for _, p := range wordlistParams {
			if !userExcludeSet[strings.ToLower(p)] {
				activeWordlist = append(activeWordlist, p)
			}
		}

		reflectedWLGet := probeWordlistReflectionGet(sess, targetURL, activeWordlist, 20, log)
		for _, p := range activeWordlist {
			val, ok := reflectedWLGet[p]
			if !ok {
				continue
			}
			key := "GET|" + strings.ToLower(originPath) + "|" + strings.ToLower(p)
			if seen[key] {
				continue
			}
			seen[key] = true
			param := models.NewParameter()
			param.ParamName = p
			param.ParamValue = val
			param.ActionURL = originPath
			param.Location = "GET"
			parameters = append(parameters, param)
		}

		reflectedWLPost := probeWordlistReflectionPost(sess, targetURL, activeWordlist, 20, log)
		for _, p := range activeWordlist {
			val, ok := reflectedWLPost[p]
			if !ok {
				continue
			}
			key := "POST|" + strings.ToLower(originPath) + "|" + strings.ToLower(p)
			if seen[key] {
				continue
			}
			seen[key] = true
			param := models.NewParameter()
			param.ParamName = p
			param.ParamValue = val
			param.ActionURL = originPath
			param.Location = "POST"
			parameters = append(parameters, param)
		}
	} else {
		var activeGeneral, activeRedirect []string
		for _, p := range config.GeneralParams {
			if !userExcludeSet[strings.ToLower(p)] {
				activeGeneral = append(activeGeneral, p)
			}
		}
		for _, p := range config.RedirectParams {
			if !userExcludeSet[strings.ToLower(p)] {
				activeRedirect = append(activeRedirect, p)
			}
		}

		families := []struct {
			name   string
			params []string
		}{
			{"GENERAL_PARAMS", activeGeneral},
			{"REDIRECT_PARAMS", activeRedirect},
		}
		for _, fam := range families {
			refGet := probeParamReflectionGet(sess, targetURL, fam.params, fam.name, log)
			for _, p := range fam.params {
				val, ok := refGet[p]
				if !ok {
					continue
				}
				key := "GET|" + strings.ToLower(originPath) + "|" + strings.ToLower(p)
				if seen[key] {
					continue
				}
				seen[key] = true
				param := models.NewParameter()
				param.ParamName = p
				param.ParamValue = val
				param.ActionURL = originPath
				param.Location = "GET"
				parameters = append(parameters, param)
			}

			refPost := probeParamReflectionPost(sess, targetURL, fam.params, fam.name, log)
			for _, p := range fam.params {
				val, ok := refPost[p]
				if !ok {
					continue
				}
				key := "POST|" + strings.ToLower(originPath) + "|" + strings.ToLower(p)
				if seen[key] {
					continue
				}
				seen[key] = true
				param := models.NewParameter()
				param.ParamName = p
				param.ParamValue = val
				param.ActionURL = originPath
				param.Location = "POST"
				parameters = append(parameters, param)
			}
		}
	}

	for name, val := range customPostfields {
		if userExcludeSet[strings.ToLower(name)] {
			continue
		}
		key := "POST|" + strings.ToLower(originPath) + "|" + strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		value := val
		if value == "" {
			value = utils.RandomString(9)
		}
		p := models.NewParameter()
		p.ParamName = name
		p.ParamValue = value
		p.ActionURL = originPath
		p.Location = "POST"
		parameters = append(parameters, p)
	}

	if len(excludeParams) > 0 {
		var filtered []*models.Parameter
		for _, p := range parameters {
			if !userExcludeSet[strings.ToLower(p.ParamName)] {
				filtered = append(filtered, p)
			}
		}
		parameters = filtered
	}

	if log != nil && !log.Silent {
		log.Info(fmt.Sprintf("parameter discovery completed: found %d parameter(s)", len(parameters)))
		for _, p := range parameters {
			fmt.Printf("\033[1m\033[32m[+]\033[0m [%s] \033[38;5;116m'%s'\033[0m -> \033[38;5;110m%s\033[0m\n",
				p.Location, p.ParamName, p.ActionURL)
		}
	}

	return parameters
}

func mapKeysInOrder(order []string, values map[string]string) []string {
	var keys []string
	seen := map[string]bool{}
	for _, k := range order {
		if seen[k] {
			continue
		}
		if _, ok := values[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	return keys
}

func chunkStrings(items []string, size int) [][]string {
	var chunks [][]string
	for i := 0; i < len(items); i += size {
		end := i + size
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[i:end])
	}
	return chunks
}

func stripFragment(raw string) string {
	parsed, err := urlParse(raw)
	if err != nil {
		return raw
	}
	parsed.Fragment = ""
	return parsed.String()
}
