// Package crawler implements the internal spider that discovers endpoints and forms.
package crawler

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/zapstiko/xsshunts/browser"
	"github.com/zapstiko/xsshunts/logger"
	"github.com/zapstiko/xsshunts/utils"
)

// IgnoredExtensions are static/binary asset suffixes skipped while crawling.
var IgnoredExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".webp": true, ".bmp": true,
	".css": true, ".js": true, ".json": true, ".xml": true, ".txt": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".mkv": true, ".webm": true, ".wav": true,
}

// Target is one crawl-discovered scan target.
type Target struct {
	URL        string
	Method     string // GET | POST
	Postfields map[string]string
	SourceURL  string
	Depth      int
}

// NormalizeCrawlURL strips the fragment identifier from a URL.
func NormalizeCrawlURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.Fragment = ""
	return parsed.String()
}

// URLSignature builds a dedup signature (scheme, host, path, sorted query keys).
func URLSignature(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	keys := make([]string, 0, len(parsed.Query()))
	for k := range parsed.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return fmt.Sprintf("%s|%s|%s|%s", strings.ToLower(parsed.Scheme), strings.ToLower(parsed.Host),
		strings.TrimSuffix(parsed.Path, "/"), strings.Join(keys, ","))
}

// FormSignature builds a form dedup signature.
func FormSignature(method, actionURL string, paramNames []string) string {
	parsed, err := url.Parse(actionURL)
	normAction := actionURL
	if err == nil {
		normAction = fmt.Sprintf("%s://%s%s", strings.ToLower(parsed.Scheme), strings.ToLower(parsed.Host), strings.TrimSuffix(parsed.Path, "/"))
	}
	names := append([]string(nil), paramNames...)
	sort.Strings(names)
	return strings.ToUpper(method) + "|" + normAction + "|" + strings.Join(names, ",")
}

// Run crawls a seed URL breadth-first and returns unique discovered targets.
func Run(sess *browser.Session, seedURL string, maxDepth, maxURLs int, log *logger.Logger) []Target {
	if maxDepth < 1 {
		maxDepth = 1
	}
	if maxDepth > 5 {
		maxDepth = 5
	}
	if maxURLs < 1 {
		maxURLs = 1
	}
	if maxURLs > 200 {
		maxURLs = 200
	}

	if log != nil {
		log.Action(fmt.Sprintf("running crawler on %s (depth=%d, max_urls=%d)...", seedURL, maxDepth, maxURLs))
	}

	visited := map[string]bool{}
	seenURLSigs := map[string]bool{}
	seenFormSigs := map[string]bool{}
	var discovered []Target

	parsedSeed, err := url.Parse(seedURL)
	if err != nil {
		return discovered
	}
	seedHost := strings.ToLower(parsedSeed.Host)

	cleanSeed := NormalizeCrawlURL(seedURL)
	seenURLSigs[URLSignature(cleanSeed)] = true

	type queueItem struct {
		url   string
		depth int
	}
	queue := []queueItem{{url: cleanSeed}}

	for len(queue) > 0 && len(discovered) < maxURLs {
		current := queue[0]
		queue = queue[1:]

		normCurrent := NormalizeCrawlURL(current.url)
		if visited[normCurrent] {
			continue
		}
		visited[normCurrent] = true

		if log != nil {
			log.Debug(fmt.Sprintf("crawling page: %s (depth=%d)", current.url, current.depth))
		}

		resp, err := sess.Goto(current.url)
		_ = resp
		if err != nil {
			if log != nil {
				log.Debug(fmt.Sprintf("crawl navigation failed on %s: %s", current.url, utils.CleanErrorText(err.Error())))
			}
			continue
		}
		sess.WaitForTimeout(500)
		html, err := sess.Content()
		if err != nil {
			continue
		}
		root := utils.ParseHTML(html)
		if root == nil {
			continue
		}

		for _, form := range utils.CollectForms(root) {
			if len(discovered) >= maxURLs {
				break
			}
			actionURL := resolveReference(current.url, form.Action)
			parsedAction, err := url.Parse(actionURL)
			if err != nil || strings.ToLower(parsedAction.Host) != seedHost {
				continue
			}

			var paramNames []string
			seenName := map[string]bool{}
			for _, f := range form.Fields {
				name := strings.TrimSpace(f.Name)
				if name != "" && !seenName[name] {
					seenName[name] = true
					paramNames = append(paramNames, name)
				}
			}
			if len(paramNames) == 0 {
				continue
			}

			formSig := FormSignature(form.Method, actionURL, paramNames)
			if seenFormSigs[formSig] {
				if log != nil {
					log.Debug(fmt.Sprintf("duplicate form skipped: [%s] %s (%s)", form.Method, actionURL, strings.Join(paramNames, ", ")))
				}
				continue
			}
			seenFormSigs[formSig] = true

			if form.Method == "POST" {
				postfields := map[string]string{}
				for _, p := range paramNames {
					postfields[p] = ""
				}
				discovered = append(discovered, Target{
					URL: actionURL, Method: "POST", Postfields: postfields,
					SourceURL: current.url, Depth: current.depth,
				})
				if log != nil {
					log.Success(fmt.Sprintf("[crawl] discovered form [POST] %s (%s)", actionURL, strings.Join(paramNames, ", ")))
				}
			} else {
				var pairs []utils.KV
				for _, p := range paramNames {
					pairs = append(pairs, utils.KV{Key: p, Value: ""})
				}
				sep := "?"
				if strings.Contains(actionURL, "?") {
					sep = "&"
				}
				getURL := actionURL + sep + utils.BuildQueryOrdered(pairs)
				sig := URLSignature(getURL)
				if !seenURLSigs[sig] {
					seenURLSigs[sig] = true
					discovered = append(discovered, Target{URL: getURL, Method: "GET", SourceURL: current.url, Depth: current.depth})
					if log != nil {
						log.Success(fmt.Sprintf("[crawl] discovered form [GET] %s (%s)", actionURL, strings.Join(paramNames, ", ")))
					}
				}
			}
		}

		if current.depth < maxDepth {
			for _, href := range utils.CollectLinks(root) {
				if len(discovered) >= maxURLs {
					break
				}
				href = strings.TrimSpace(href)
				if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") ||
					strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "tel:") {
					continue
				}
				absURL := resolveReference(current.url, href)
				parsedLink, err := url.Parse(absURL)
				if err != nil || (parsedLink.Scheme != "http" && parsedLink.Scheme != "https") {
					continue
				}
				if strings.ToLower(parsedLink.Host) != seedHost {
					continue
				}
				if IgnoredExtensions[strings.ToLower(path.Ext(parsedLink.Path))] {
					continue
				}

				cleanLink := NormalizeCrawlURL(absURL)
				sig := URLSignature(cleanLink)
				if seenURLSigs[sig] {
					continue
				}
				seenURLSigs[sig] = true

				discovered = append(discovered, Target{URL: cleanLink, Method: "GET", SourceURL: current.url, Depth: current.depth + 1})
				if log != nil {
					log.Success(fmt.Sprintf("[crawl] discovered link: %s (depth=%d)", cleanLink, current.depth+1))
				}

				if !visited[cleanLink] {
					queue = append(queue, queueItem{url: cleanLink, depth: current.depth + 1})
				}
			}
		}
	}

	if log != nil {
		log.Action(fmt.Sprintf("crawler finished: %d unique endpoint(s) collected", len(discovered)))
	}
	return discovered
}

func resolveReference(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}
