package s3verify

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	v4CredPrefix         = "Credential="
	v4SignedHeaderPrefix = "SignedHeaders="
	v4SignaturePrefix    = "Signature="
	v4SignAlgorithm      = "AWS4-HMAC-SHA256"
	s3Authorization      = "Authorization"
)

type v4ParsedData struct {
	AKey          string
	Date          string
	Region        string
	RequestType   string
	Service       string
	Algorithm     string
	SignedHeaders []string
	Signature     string
	Contentmd5    string
	Contentsha256 string
}

func ParseV4Signature(r *http.Request) (*v4ParsedData, bool, error) {
	auz := r.Header.Get("Authorization")
	if len(auz) == 0 {
		return nil, false, nil
	}
	items := strings.Split(auz, ",")
	if len(items) != 3 {
		return nil, false, fmt.Errorf("invalid authorization part, auz:%s", auz)
	}
	v4Data := &v4ParsedData{}
	credPart := strings.TrimSpace(items[0])
	if err := v4Data.parseCredPart(credPart); err != nil {
		return nil, false, fmt.Errorf("decode cred part fail, err:%w", err)
	}
	signedHeaderPart := strings.TrimSpace(items[1])
	if err := v4Data.parseSignedHeaderPart(signedHeaderPart); err != nil {
		return nil, false, fmt.Errorf("decode signature header part fail, err:%w", err)
	}
	signaturePart := strings.TrimSpace(items[2])
	if err := v4Data.parseSignaturePart(signaturePart); err != nil {
		return nil, false, fmt.Errorf("decode signature part fail, err:%w", err)
	}
	if err := v4Data.parseExtraPart(r); err != nil {
		return nil, false, fmt.Errorf("decode extra part fail, err:%w", err)
	}
	return v4Data, true, nil
}

func (d *v4ParsedData) parseExtraPart(r *http.Request) error {
	d.Contentmd5 = r.Header.Get("Content-Md5")
	d.Contentsha256 = r.Header.Get("X-Amz-Content-Sha256")
	d.Date = r.Header.Get("X-Amz-Date")
	return nil
}

func (d *v4ParsedData) parseCredPart(part string) error {
	items := strings.Split(part, " ")
	if len(items) != 2 {
		return fmt.Errorf("invalid cred part, part:%s", part)
	}
	algo := strings.TrimSpace(items[0])
	d.Algorithm = algo
	cred := strings.TrimSpace(items[1])
	if !strings.HasPrefix(cred, v4CredPrefix) {
		return fmt.Errorf("invalid cred prefix, cred:%s", cred)
	}
	cred = cred[len(v4CredPrefix):]
	parts := strings.Split(cred, "/")
	if len(parts) != 5 {
		return fmt.Errorf("invalid cred part, need 5, part:%s", cred)
	}
	d.AKey = parts[0]
	d.Date = parts[1]
	d.Region = parts[2]
	d.Service = parts[3]
	d.RequestType = parts[4]
	return nil
}

func (d *v4ParsedData) parseSignedHeaderPart(part string) error {
	part = strings.TrimSpace(part)
	if !strings.HasPrefix(part, v4SignedHeaderPrefix) {
		return fmt.Errorf("invalid sign header, should containsm signed headers prefix, part:%s", part)
	}
	part = part[len(v4SignedHeaderPrefix):]
	headers := strings.Split(part, ";")
	for _, h := range headers {
		d.SignedHeaders = append(d.SignedHeaders, strings.TrimSpace(h))
	}
	return nil
}

func (d *v4ParsedData) parseSignaturePart(part string) error {
	if !strings.HasPrefix(part, v4SignaturePrefix) {
		return fmt.Errorf("invalid signature prefix, signature:%s", part)
	}
	part = part[len(v4SignaturePrefix):]
	d.Signature = strings.TrimSpace(part)
	return nil
}
