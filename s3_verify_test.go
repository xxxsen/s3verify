package s3verify

import (
	"context"
	"net/http"
	"testing"

	awsauth "github.com/smartystreets/s3"
	"github.com/stretchr/testify/assert"
)

func mapQuery(m map[string]string) UserQueryFunc {
	return func(ctx context.Context, ak string) (string, bool, error) {
		sk, ok := m[ak]
		return sk, ok, nil
	}
}

func TestVerifyPut(t *testing.T) {
	req, err := awsauth.NewRequest(
		http.MethodPut,
		awsauth.Credentials("abc", "123456"),
		awsauth.ContentBytes([]byte("helloworld")),
		awsauth.Bucket("hackmd"),
		awsauth.Endpoint("http://test.com:80"),
		awsauth.Key("abcd"),
	)
	assert.NoError(t, err)
	_, ok, err := Verify(context.Background(), req, mapQuery(map[string]string{"abc": "123456"}))
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyGet(t *testing.T) {
	req, err := awsauth.NewRequest(
		http.MethodGet,
		awsauth.Credentials("abc", "123456"),
		awsauth.Bucket("hackmd"),
		awsauth.Endpoint("https://127.0.0.1:443"),
		awsauth.Key("abcd"),
	)
	assert.NoError(t, err)
	_, ok, err := Verify(context.Background(), req, mapQuery(map[string]string{"abc": "123456"}))
	assert.NoError(t, err)
	assert.True(t, ok)
}
