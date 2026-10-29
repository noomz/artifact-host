package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3 struct {
	client *s3.Client
	bucket string
	prefix string
}

type S3Opts struct {
	Bucket    string
	Prefix    string
	Endpoint  string
	Region    string
	PathStyle bool
}

func NewS3(ctx context.Context, opts S3Opts) (*S3, error) {
	if opts.Bucket == "" {
		return nil, errors.New("s3 bucket required")
	}
	region := opts.Region
	if region == "" {
		region = "us-east-1"
	}
	loadOpts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, err
	}
	var s3opts []func(*s3.Options)
	if opts.Endpoint != "" {
		ep := opts.Endpoint
		s3opts = append(s3opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(ep)
			o.UsePathStyle = true
		})
	} else if opts.PathStyle {
		s3opts = append(s3opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}
	return &S3{
		client: s3.NewFromConfig(cfg, s3opts...),
		bucket: opts.Bucket,
		prefix: strings.Trim(opts.Prefix, "/"),
	}, nil
}

func (s *S3) key(key string) string {
	if s.prefix == "" {
		return key
	}
	return s.prefix + "/" + key
}

func (s *S3) Put(ctx context.Context, key string, body []byte, contentType string) error {
	in := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(key)),
		Body:   bytes.NewReader(body),
	}
	if contentType != "" {
		in.ContentType = aws.String(contentType)
	}
	_, err := s.client.PutObject(ctx, in)
	return err
}

func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, string, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(key)),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) || strings.Contains(err.Error(), "NoSuchKey") {
			return nil, "", ErrNotFound
		}
		return nil, "", err
	}
	ctype := ""
	if out.ContentType != nil {
		ctype = *out.ContentType
	}
	return out.Body, ctype, nil
}
