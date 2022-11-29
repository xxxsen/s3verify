package s3verify

import (
	"encoding/hex"
	"fmt"
	"net/http"
)

func calculateAWSv4Signature(region string, request *http.Request, credentials awsCredentials, v4data *V4Signature) string {
	signer := newV4Signer("s3", region, request.Header.Get("X-Amz-Content-Sha256"), request, credentials, v4data)
	signature := signer.calculateSignature()
	return signature.task4_AuthorizationHeader
}

type v4Signer struct {
	keys awsCredentials
	data *v4RequestData
}

func newV4Signer(service, region, bodyDigest string,
	request *http.Request,
	credentials awsCredentials,
	v4data *V4Signature) *v4Signer {
	return &v4Signer{
		keys: credentials,
		data: initializeRequestData(request, service, region, bodyDigest, v4data.SignedHeaders),
	}
}

type v4Signature struct {
	task1_CanonicalRequest      string
	task2_StringToSign          string
	task3_IntermediateSignature string
	task4_AuthorizationHeader   string
}

func (s *v4Signer) calculateSignature() v4Signature {
	task1 := s.task1_CanonicalRequest()
	task2 := s.task2_StringToSign(task1)
	task3 := s.task3_IntermediateSignature(task2)
	task4 := s.task4_AuthorizationHeader(task3)
	return v4Signature{
		task1_CanonicalRequest:      task1,
		task2_StringToSign:          task2,
		task3_IntermediateSignature: task3,
		task4_AuthorizationHeader:   task4,
	}
}

// TASK 1: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
func (s *v4Signer) task1_CanonicalRequest() string {
	return join("\n",
		s.data.method,
		s.data.urlPath,
		s.data.urlQuery,
		s.data.canonicalHeaders,
		s.data.signedHeaders,
		s.data.bodyDigest,
	)
}

// TASK 2: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
func (s *v4Signer) task2_StringToSign(canonicalRequest string) string {
	return join("\n",
		awsV4SignatureAlgorithm,
		s.data.timestamp,
		s.data.credentialScope(),
		hashSHA256([]byte(canonicalRequest)),
	)
}

// TASK 3: https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
func (s *v4Signer) task3_IntermediateSignature(stringToSign string) string {
	signingKey := []byte(awsV4SignatureInitializationString + s.keys.SecretAccessKey)
	signingKey = hmacSHA256(signingKey, s.data.date)
	signingKey = hmacSHA256(signingKey, s.data.region)
	signingKey = hmacSHA256(signingKey, s.data.service)
	signingKey = hmacSHA256(signingKey, awsV4CredentialScopeTerminationString)
	signingKey = hmacSHA256(signingKey, stringToSign)
	return hex.EncodeToString(signingKey)
}

// TASK 4: https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
func (s *v4Signer) task4_AuthorizationHeader(signature string) string {
	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		awsV4SignatureAlgorithm,
		s.keys.AccessKeyID,
		s.data.credentialScope(),
		s.data.signedHeaders,
		signature,
	)
}

const (
	awsV4SignatureInitializationString    = "AWS4"
	awsV4CredentialScopeTerminationString = "aws4_request"
	awsV4SignatureAlgorithm               = "AWS4-HMAC-SHA256"
)
