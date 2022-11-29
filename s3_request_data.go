package s3verify

import (
	"net/http"
)

type v4RequestData struct {
	service          string
	region           string
	method           string
	urlPath          string
	urlQuery         string
	bodyDigest       string
	timestamp        string
	date             string
	canonicalHeaders string
	signedHeaders    string
}

func initializeRequestData(request *http.Request, service, region, bodyDigest string, v4data *v4ParsedData) *v4RequestData {
	requestTimestamp := request.Header.Get("X-Amz-Date")
	canonicalHeaders, signedHeaders := canonicalAndSignedHeaders(request, v4data)
	return &v4RequestData{
		service:          service,
		region:           region,
		method:           request.Method,
		urlPath:          normalizeURI(request.URL.Path),
		urlQuery:         normalizeQuery(request.URL.Query()),
		bodyDigest:       bodyDigest,
		timestamp:        requestTimestamp,
		date:             timestampDateV4(requestTimestamp),
		canonicalHeaders: canonicalHeaders,
		signedHeaders:    signedHeaders,
	}
}

func (r v4RequestData) credentialScope() string {
	return join("/", r.date, r.region, r.service, awsV4CredentialScopeTerminationString)
}

func timestampDateV4(timestamp string) string { return timestamp[:8] }
