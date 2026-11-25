package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const defaultContentType = "application/octet-stream"

// Config holds S3-compatible object storage configuration (AWS S3, Cloudflare R2, LocalStack, MinIO).
type Config struct {
	EndpointURL     string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	ForcePathStyle  bool
	PartSize        int64
	Concurrency     int
}

// Validate checks that required configuration fields are present and well-formed.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Bucket) == "" {
		return errors.New("storage: bucket is required")
	}
	if strings.TrimSpace(c.Region) == "" {
		return errors.New("storage: region is required")
	}
	if (c.AccessKeyID == "") != (c.SecretAccessKey == "") {
		return errors.New("storage: both access key ID and secret access key must be provided together")
	}
	if c.EndpointURL != "" {
		u, err := url.Parse(c.EndpointURL)
		if err != nil {
			return fmt.Errorf("storage: invalid endpoint URL: %w", err)
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("storage: endpoint URL must include http/https scheme and host: %q", c.EndpointURL)
		}
	}
	if c.PartSize < 0 || (c.PartSize > 0 && c.PartSize < manager.MinUploadPartSize) {
		return fmt.Errorf("storage: part size must be 0 or at least %d bytes", manager.MinUploadPartSize)
	}
	if c.Concurrency < 0 {
		return errors.New("storage: concurrency must be non-negative")
	}
	return nil
}

// UploadResult describes the completed S3 object upload.
type UploadResult struct {
	Bucket   string
	Key      string
	ETag     string
	Location string
}

// Client wraps an AWS SDK v2 S3 client and streaming multipart uploader for a configured bucket.
type Client struct {
	bucket   string
	region   string
	s3       *s3.Client
	uploader *manager.Uploader
}

// NewClient initializes a new S3 storage Client after validating cfg.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	loadOpts := []func(*config.LoadOptions) error{
		config.WithRegion(cfg.Region),
	}
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		loadOpts = append(loadOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("storage: load AWS config: %w", err)
	}

	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.ForcePathStyle
		if cfg.EndpointURL != "" {
			o.BaseEndpoint = aws.String(cfg.EndpointURL)
		}
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})

	uploader := manager.NewUploader(s3Client, func(u *manager.Uploader) {
		if cfg.PartSize > 0 {
			u.PartSize = cfg.PartSize
		} else {
			u.PartSize = manager.DefaultUploadPartSize
		}
		if cfg.Concurrency > 0 {
			u.Concurrency = cfg.Concurrency
		}
		// Abort incomplete multipart uploads automatically if streaming fails or ctx is canceled.
		u.LeavePartsOnError = false
	})

	return &Client{
		bucket:   cfg.Bucket,
		region:   cfg.Region,
		s3:       s3Client,
		uploader: uploader,
	}, nil
}

// EnsureBucket verifies that the configured bucket exists, creating it if missing.
func (c *Client) EnsureBucket(ctx context.Context) error {
	_, err := c.s3.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(c.bucket),
	})
	if err == nil {
		return nil
	}
	if !isNotFoundError(err) {
		return fmt.Errorf("storage: check bucket %q: %w", c.bucket, err)
	}

	input := &s3.CreateBucketInput{
		Bucket: aws.String(c.bucket),
	}
	if c.region != "" && c.region != "us-east-1" {
		input.CreateBucketConfiguration = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(c.region),
		}
	}

	if _, createErr := c.s3.CreateBucket(ctx, input); createErr != nil {
		if isBucketAlreadyExistsError(createErr) {
			return nil
		}
		return fmt.Errorf("storage: create bucket %q: %w", c.bucket, createErr)
	}
	return nil
}

// UploadStream streams data from r directly to S3 using multipart upload without buffering the full stream in memory.
func (c *Client) UploadStream(ctx context.Context, key string, r io.Reader, contentType string) (UploadResult, error) {
	if strings.TrimSpace(key) == "" {
		return UploadResult{}, errors.New("storage: object key is required")
	}
	if r == nil {
		return UploadResult{}, errors.New("storage: reader must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return UploadResult{}, fmt.Errorf("storage: upload %q canceled: %w", key, err)
	}
	if strings.TrimSpace(contentType) == "" {
		contentType = defaultContentType
	}

	out, err := c.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(key),
		Body:        r,
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return UploadResult{}, fmt.Errorf("storage: upload %q: %w", key, err)
	}

	return UploadResult{
		Bucket:   c.bucket,
		Key:      key,
		ETag:     aws.ToString(out.ETag),
		Location: out.Location,
	}, nil
}

// DownloadStream opens a streaming reader for the specified S3 object.
// Callers are responsible for closing the returned io.ReadCloser.
func (c *Client) DownloadStream(ctx context.Context, key string) (io.ReadCloser, error) {
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("storage: object key is required")
	}

	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("storage: download %q: %w", key, err)
	}
	return out.Body, nil
}

// DeleteObject removes the specified object from the configured S3 bucket.
// Missing objects (NoSuchKey / HTTP 404) are treated as idempotent success.
func (c *Client) DeleteObject(ctx context.Context, key string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("storage: object key is required")
	}

	if _, err := c.s3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	}); err != nil {
		if IsNotFoundError(err) {
			return nil
		}
		return fmt.Errorf("storage: delete %q: %w", key, err)
	}
	return nil
}

// DeleteObjects removes multiple objects in batches (up to 1000 keys per request).
// Missing objects (NoSuchKey / NotFound) are ignored cleanly.
func (c *Client) DeleteObjects(ctx context.Context, keys []string) error {
	seen := make(map[string]struct{}, len(keys))
	clean := make([]types.ObjectIdentifier, 0, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		clean = append(clean, types.ObjectIdentifier{Key: aws.String(k)})
	}
	if len(clean) == 0 {
		return nil
	}

	const maxBatchSize = 1000
	for start := 0; start < len(clean); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(clean) {
			end = len(clean)
		}

		out, err := c.s3.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(c.bucket),
			Delete: &types.Delete{
				Objects: clean[start:end],
				Quiet:   aws.Bool(true),
			},
		})
		if err != nil {
			if IsNotFoundError(err) {
				continue
			}
			return fmt.Errorf("storage: batch delete objects: %w", err)
		}

		var batchErrs []error
		for _, delErr := range out.Errors {
			code := aws.ToString(delErr.Code)
			if code == "NoSuchKey" || code == "NotFound" {
				continue
			}
			batchErrs = append(batchErrs, fmt.Errorf("key %q (%s): %s", aws.ToString(delErr.Key), code, aws.ToString(delErr.Message)))
		}
		if len(batchErrs) > 0 {
			return fmt.Errorf("storage: batch delete failed: %w", errors.Join(batchErrs...))
		}
	}
	return nil
}

// IsNotFoundError reports whether err represents an S3/R2/LocalStack not-found condition (404, NotFound, NoSuchKey, NoSuchBucket).
func IsNotFoundError(err error) bool {
	return isNotFoundError(err)
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusNotFound {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NotFound", "NoSuchBucket", "NoSuchKey", "404":
			return true
		}
	}
	return false
}

func isBucketAlreadyExistsError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "BucketAlreadyOwnedByYou", "BucketAlreadyExists":
			return true
		}
	}
	return false
}
