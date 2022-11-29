package s3verify

import (
	"net/http"
	"strings"

	"github.com/xxxsen/common/errs"
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
		return nil, false, errs.New(errs.ErrParam, "invalid authorization part, auz:%s", auz)
	}
	v4Data := &v4ParsedData{}
	credPart := strings.TrimSpace(items[0])
	if err := v4Data.parseCredPart(credPart); err != nil {
		return nil, false, errs.Wrap(errs.ErrParam, "decode cred part fail", err)
	}
	signedHeaderPart := strings.TrimSpace(items[1])
	if err := v4Data.parseSignedHeaderPart(signedHeaderPart); err != nil {
		return nil, false, errs.Wrap(errs.ErrParam, "decode signature header part fail", err)
	}
	signaturePart := strings.TrimSpace(items[2])
	if err := v4Data.parseSignaturePart(signaturePart); err != nil {
		return nil, false, errs.Wrap(errs.ErrParam, "decode signature part fail", err)
	}
	if err := v4Data.parseExtraPart(r); err != nil {
		return nil, false, errs.Wrap(errs.ErrParam, "decode extra part fail", err)
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
		return errs.New(errs.ErrParam, "invalid cred part, part:%s", part)
	}
	algo := strings.TrimSpace(items[0])
	d.Algorithm = algo
	cred := strings.TrimSpace(items[1])
	if !strings.HasPrefix(cred, v4CredPrefix) {
		return errs.New(errs.ErrParam, "invalid cred prefix, cred:%s", cred)
	}
	cred = cred[len(v4CredPrefix):]
	parts := strings.Split(cred, "/")
	if len(parts) != 5 {
		return errs.New(errs.ErrParam, "invalid cred part, need 5, part:%s", cred)
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
		return errs.New(errs.ErrParam, "invalid sign header, should containsm signed headers prefix, part:%s", part)
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
		return errs.New(errs.ErrParam, "invalid signature prefix, signature:%s", part)
	}
	part = part[len(v4SignaturePrefix):]
	d.Signature = strings.TrimSpace(part)
	return nil
}
