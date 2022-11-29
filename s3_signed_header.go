package s3verify

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func canonicalAndSignedHeaders(req *http.Request, signedHeaderArr []string, original http.Header) (canonical, signed string) {
	lowercaseKeys := map[string]string{} // map[lowercase]original
	for _, key := range signedHeaderArr {
		lowercaseKeys[strings.ToLower(key)] = key
	}
	var sortedKeys []string
	for key := range lowercaseKeys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	canonicalBuilder := new(strings.Builder)
	for _, lowerKey := range sortedKeys {
		titleKey := lowercaseKeys[lowerKey]
		var values []string
		iterVals := original.Values(titleKey)
		if strings.EqualFold(titleKey, "Host") {
			iterVals = []string{req.Host} //FIXME: 如果host使用的端口是443/80,那么将端口移除
			//iterVals = []string{strings.Split(req.Host, ":")[0]} // AWS does not include port in signing request.
		}
		if strings.EqualFold(titleKey, "Content-Length") {
			iterVals = []string{strconv.FormatInt(req.ContentLength, 10)}
		}
		for _, value := range iterVals {
			values = append(values, trimHeaderValue(value))
		}
		canonicalBuilder.WriteString(lowerKey)
		canonicalBuilder.WriteString(":")
		canonicalBuilder.WriteString(strings.Join(values, ","))
		canonicalBuilder.WriteString("\n")
	}
	return canonicalBuilder.String(), strings.Join(sortedKeys, ";")
}

func trimHeaderValue(value string) string {
	value = strings.TrimSpace(value)
	for strings.Contains(value, "  ") {
		value = strings.ReplaceAll(value, "  ", " ")
	}
	return value
}
