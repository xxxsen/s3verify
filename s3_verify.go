package s3verify

import (
	"net/http"
	"strings"

	"github.com/xxxsen/common/errs"
)

func IsRequestSignatureV4(r *http.Request) bool {
	auz := r.Header.Get(s3Authorization)
	if len(auz) == 0 {
		return false
	}
	if !strings.HasPrefix(auz, awsV4SignatureAlgorithm) {
		return false
	}
	return true
}

func Verify(req *http.Request, user map[string]string) (string, bool, error) {
	if !IsRequestSignatureV4(req) {
		return "", false, errs.New(errs.ErrParam, "not v4 request")
	}
	sign, ok, err := ParseV4Signature(req)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	sk, ok := user[sign.AKey]
	if !ok {
		return "", false, nil
	}
	cred := awsCredentials{
		AccessKeyID:     sign.AKey,
		SecretAccessKey: sk,
	}
	signature := calculateAWSv4Signature(sign.Region, req, cred)
	idx := strings.Index(signature, v4SignaturePrefix)
	if idx < 0 {
		return "", false, errs.New(errs.ErrParam, "create signature fail, no prefix, sn:%s", signature)
	}
	signature = signature[idx+len(v4SignaturePrefix):]
	if signature != sign.Signature {
		return "", false, nil
	}
	return sign.AKey, true, nil
}
