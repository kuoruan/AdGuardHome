package gfwlist

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/AdguardTeam/golibs/log"
)

type gfwListRule interface {
	match(*url.URL) bool
}

type hostWildcardRule struct {
	pattern string
}

func (r *hostWildcardRule) match(u *url.URL) bool {
	if strings.Contains(u.Host, r.pattern) {
		return true
	}
	return false
}

type urlWildcardRule struct {
	pattern     string
	prefixMatch bool
}

func (r *urlWildcardRule) match(u *url.URL) bool {
	if len(u.Scheme) == 0 {
		u.Scheme = "https"
	}
	if r.prefixMatch {
		return strings.HasPrefix(u.String(), r.pattern)
	}
	return strings.Contains(u.String(), r.pattern)
}

type regexRule struct {
	pattern string
}

func (r *regexRule) match(u *url.URL) bool {
	if len(u.Scheme) == 0 {
		u.Scheme = "https"
	}
	matched, err := regexp.MatchString(r.pattern, u.String())
	if nil != err {
		log.Error("Invalid regex pattern: %s width reason: %v", r.pattern, err)
	}
	return matched
}

type whiteListRule struct {
	r gfwListRule
}

func (r *whiteListRule) match(u *url.URL) bool {
	return r.r.match(u)
}

type GFWList struct {
	fetchURL string
	ruleMap  map[string]gfwListRule
	ruleList []gfwListRule
	mutex    sync.Mutex
}

func NewGFWList(fetchURL string, interval int, opts *upstream.Options) (*GFWList, error) {
	boot := opts.Bootstrap
	if boot == nil {
		// Use the default resolver for bootstrapping.
		boot = net.DefaultResolver
	}

	bootstrap.ResolveDialContext(u, opts.Timeout, boot, opts.PreferIPv6)

	fetched, err := fetchGFWList(fetchURL)
	if err != nil {
		return nil, err
	}

	gfwList := &GFWList{
		fetchURL: fetchURL,
	}

	gfwList.setFrom(fetched)

	return gfwList, nil
}

func (gfw *GFWList) setFrom(target *GFWList) {
	gfw.mutex.Lock()
	defer gfw.mutex.Unlock()

	gfw.ruleMap = target.ruleMap
	gfw.ruleList = target.ruleList
}

func (gfw *GFWList) fastMatchDomain(u *url.URL) (matchResult bool, exist bool) {
	domain := u.Host
	rootDomain := domain
	if strings.Contains(domain, ":") {
		domain, _, _ = net.SplitHostPort(domain)
		rootDomain = domain
	}

	rule, exist := gfw.ruleMap[domain]
	if !exist {
		ss := strings.Split(domain, ".")
		if len(ss) > 2 {
			rootDomain = ss[len(ss)-2] + "." + ss[len(ss)-1]
			if len(ss[len(ss)-2]) < 4 && len(ss) >= 3 {
				rootDomain = ss[len(ss)-3] + "." + rootDomain
			}
		}
		rule, exist = gfw.ruleMap[rootDomain]
	}
	if exist {
		matched := rule.match(u)
		if _, ok := rule.(*whiteListRule); ok {
			return !matched, true
		}
		return matched, true
	}
	return false, false
}

func (gfw *GFWList) IsBlockedByGFW(host string) bool {
	gfw.mutex.Lock()
	defer gfw.mutex.Unlock()

	u, err := url.Parse(host)
	if err != nil {
		return false
	}

	fastMatchResult, exist := gfw.fastMatchDomain(u)
	if exist {
		return fastMatchResult
	}

	for _, rule := range gfw.ruleList {
		if rule.match(u) {
			if _, ok := rule.(*whiteListRule); ok {
				return false
			}
			return true
		}
	}
	return false
}

func fetchGFWList(fetchURL string) (*GFWList, error) {
	resp, err := http.Get(fetchURL)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch gfwlist failed, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	out := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
	_, err = base64.StdEncoding.Decode(out, body)
	if err != nil {
		return nil, err
	}

	// read decoded gfwlist line by line
	reader := bufio.NewReader(bytes.NewReader(out))

	gfwList := &GFWList{
		ruleMap:  make(map[string]gfwListRule),
		ruleList: make([]gfwListRule, 0),
	}

	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}

		str := strings.TrimSpace(string(line))

		// comment
		if len(str) == 0 || strings.HasPrefix(str, "!") || strings.HasPrefix(str, "[") {
			continue
		}

		var rule gfwListRule
		isWhileListRule := false
		fastMatch := false

		if strings.HasPrefix(str, "@@") {
			isWhileListRule = true
			str = str[2:]
		}

		if strings.HasPrefix(str, "/") && strings.HasSuffix(str, "/") {
			str = str[1 : len(str)-1]
			rule = &regexRule{str}
		} else {
			if strings.HasPrefix(str, "||") {
				str = str[2:]
				rule = &hostWildcardRule{str}
				fastMatch = true
			} else if strings.HasPrefix(str, "|") {
				rule = &urlWildcardRule{str[1:], true}
			} else {
				if !strings.Contains(str, "/") {
					fastMatch = true
					rule = &hostWildcardRule{str}
					if strings.HasPrefix(str, ".") {
						str = str[1:]
					}
				} else {
					rule = &urlWildcardRule{str, false}
				}
			}
		}
		if isWhileListRule {
			rule = &whiteListRule{rule}
		}
		if fastMatch {
			gfwList.ruleMap[str] = rule
		} else {
			gfwList.ruleList = append(gfwList.ruleList, rule)
		}
	}

	return gfwList, nil
}
