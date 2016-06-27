package router

import (
	"io"
	"net/http"

	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/s3"
)

type s3Upstream struct {
	S3BucketName string `json:"bucket_name"`
	AWSAccessKey string `json:"access_key"`
	AWSSecretKey string `json:"secret_key"`
	AWSRegion    string `json:"region"`
	s3Bucket     *s3.Bucket
}

func (s *s3Upstream) finalize() {
	auth := aws.Auth{AccessKey: s.AWSAccessKey, SecretKey: s.AWSSecretKey}
	s3s := s3.New(auth, aws.Regions[s.AWSRegion])
	s.s3Bucket = s3s.Bucket(s.S3BucketName)
}

func (s *s3Upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	rc, err := s.s3Bucket.GetResponse(r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	defer rc.Body.Close()
	w.Header().Set("Content-Type", rc.Header.Get("Content-Type"))
	io.Copy(w, rc.Body)
}
