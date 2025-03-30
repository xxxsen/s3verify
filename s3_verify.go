package s3verify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type UserQueryFunc func(ctx context.Context, ak string) (string, bool, error)

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

func Verify(ctx context.Context, req *http.Request, fn UserQueryFunc) (string, bool, error) {
	if !IsRequestSignatureV4(req) {
		return "", false, fmt.Errorf("not v4 request")
	}
	sign, ok, err := ParseV4Signature(req)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	sk, ok, err := fn(ctx, sign.AKey)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	cred := awsCredentials{
		AccessKeyID:     sign.AKey,
		SecretAccessKey: sk,
	}
	signature := calculateAWSv4Signature(sign.Region, req, cred, sign)
	idx := strings.Index(signature, v4SignaturePrefix)
	if idx < 0 {
		return "", false, fmt.Errorf("create signature fail, no prefix, sn:%s", signature)
	}
	signature = signature[idx+len(v4SignaturePrefix):]
	if signature != sign.Signature {
		return "", false, nil
	}
	return sign.AKey, true, nil
}
