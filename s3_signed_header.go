package s3verify

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func canonicalAndSignedHeaders(req *http.Request, v4data *v4ParsedData) (canonical, signed string) {
	sortedKeys := make([]string, 0, len(v4data.SignedHeaders))
	sortedKeys = append(sortedKeys, v4data.SignedHeaders...)
	sort.Strings(sortedKeys)

	canonicalBuilder := new(strings.Builder)
	for _, key := range sortedKeys {
		var values []string
		iterVals := req.Header.Values(key)
		if strings.EqualFold(key, "Host") {
			iterVals = []string{req.Host} //FIXME: 如果host使用的端口是443/80,那么将端口移除
			//iterVals = []string{strings.Split(req.Host, ":")[0]} // AWS does not include port in signing request.
		}
		if strings.EqualFold(key, "Content-Length") {
			iterVals = []string{strconv.FormatInt(req.ContentLength, 10)}
		}
		for _, value := range iterVals {
			values = append(values, trimHeaderValue(value))
		}
		canonicalBuilder.WriteString(key)
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
