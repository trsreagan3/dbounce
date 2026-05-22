package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock S3 client for object-storage tests
// ---------------------------------------------------------------------------

type mockObjectStorageS3 struct {
	mu sync.Mutex

	headErr    error
	putErr     error
	deleteErr  error
	puts       []mockS3PutObject
	deletes    []mockS3DeleteObject
	headCalls  int
}

type mockS3DeleteObject struct {
	Bucket string
	Key    string
}

func (m *mockObjectStorageS3) HeadBucket(
	ctx context.Context, in *s3.HeadBucketInput, optFns ...func(*s3.Options),
) (*s3.HeadBucketOutput, error) {
	m.mu.Lock()
	m.headCalls++
	m.mu.Unlock()
	if m.headErr != nil {
		return nil, m.headErr
	}
	return &s3.HeadBucketOutput{}, nil
}

func (m *mockObjectStorageS3) PutObject(
	ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	body := bytes.Buffer{}
	if in.Body != nil {
		_, _ = body.ReadFrom(in.Body)
	}
	m.mu.Lock()
	m.puts = append(m.puts, mockS3PutObject{
		Bucket: aws.ToString(in.Bucket),
		Key:    aws.ToString(in.Key),
		Body:   append([]byte{}, body.Bytes()...),
	})
	m.mu.Unlock()
	return &s3.PutObjectOutput{}, nil
}

func (m *mockObjectStorageS3) DeleteObject(
	ctx context.Context, in *s3.DeleteObjectInput, optFns ...func(*s3.Options),
) (*s3.DeleteObjectOutput, error) {
	if m.deleteErr != nil {
		return nil, m.deleteErr
	}
	m.mu.Lock()
	m.deletes = append(m.deletes, mockS3DeleteObject{
		Bucket: aws.ToString(in.Bucket),
		Key:    aws.ToString(in.Key),
	})
	m.mu.Unlock()
	return &s3.DeleteObjectOutput{}, nil
}

func (m *mockObjectStorageS3) Puts() []mockS3PutObject {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mockS3PutObject, len(m.puts))
	copy(out, m.puts)
	return out
}

func (m *mockObjectStorageS3) HeadCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.headCalls
}

// ---------------------------------------------------------------------------
// Defaults sanity
// ---------------------------------------------------------------------------

func TestObjectStorageDefaultsMatchSpec(t *testing.T) {
	// Cross-product invariant: same default values across all four
	// products. ibounce + dbounce + gbounce assert these byte-for-byte
	// in their own tests.
	assert.Equal(t, 5, ObjectStorageDefaultRotationMinutes)
	assert.Equal(t, 16, ObjectStorageDefaultMaxSizeMB)
	assert.Equal(t, "us-east-1", ObjectStorageDefaultRegion)
}

// ---------------------------------------------------------------------------
// Credentials resolution
// ---------------------------------------------------------------------------

func TestLoadObjectStorageCredentialsFromEnv(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA-test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-test")
	t.Setenv("AWS_SESSION_TOKEN", "")
	c, err := LoadObjectStorageCredentials("")
	require.NoError(t, err)
	assert.Equal(t, "AKIA-test", c.AccessKeyID)
	assert.Equal(t, "secret-test", c.SecretAccessKey)
	assert.Equal(t, "", c.SessionToken)
}

func TestLoadObjectStorageCredentialsFromEnvWithSessionToken(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "k")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "s")
	t.Setenv("AWS_SESSION_TOKEN", "tok")
	c, err := LoadObjectStorageCredentials("")
	require.NoError(t, err)
	assert.Equal(t, "tok", c.SessionToken)
}

func TestLoadObjectStorageCredentialsMissingEnvRaises(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	_, err := LoadObjectStorageCredentials("")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrObjectStorageNoCredentials)
}

func TestLoadObjectStorageCredentialsFileOverridesEnv(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "env-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.yaml")
	contents := "access_key_id: file-key\n" +
		"secret_access_key: file-secret\n" +
		"session_token: file-token\n"
	require.NoError(t, os.WriteFile(p, []byte(contents), 0o600))
	c, err := LoadObjectStorageCredentials(p)
	require.NoError(t, err)
	// File wins.
	assert.Equal(t, "file-key", c.AccessKeyID)
	assert.Equal(t, "file-secret", c.SecretAccessKey)
	assert.Equal(t, "file-token", c.SessionToken)
}

func TestLoadObjectStorageCredentialsINIFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.ini")
	contents := "[default]\n" +
		"access_key_id=ini-key\n" +
		"secret_access_key=ini-secret\n"
	require.NoError(t, os.WriteFile(p, []byte(contents), 0o600))
	c, err := LoadObjectStorageCredentials(p)
	require.NoError(t, err)
	assert.Equal(t, "ini-key", c.AccessKeyID)
	assert.Equal(t, "ini-secret", c.SecretAccessKey)
}

func TestLoadObjectStorageCredentialsFileMissingRaises(t *testing.T) {
	_, err := LoadObjectStorageCredentials("/nonexistent/creds.yaml")
	require.Error(t, err)
}

func TestLoadObjectStorageCredentialsFileIncompleteRaises(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.yaml")
	require.NoError(t, os.WriteFile(p, []byte("access_key_id: k\n"), 0o600))
	_, err := LoadObjectStorageCredentials(p)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Partition path + instance id
// ---------------------------------------------------------------------------

func TestObjectStoragePartitionPathFormatLocked(t *testing.T) {
	// Hive-style partition layout. Athena / BigQuery / Spark / Trino
	// all auto-discover from this shape; the integration test + docs
	// cite the exact string.
	when := time.Date(2026, 5, 22, 14, 7, 33, 0, time.UTC)
	path := objectStoragePartitionPath(
		"bounce-audit/prod", "dbounce", "host42-12345",
		when, 1747920453000,
	)
	assert.Equal(t,
		"bounce-audit/prod/year=2026/month=05/day=22/hour=14/"+
			"dbounce-host42-12345-1747920453000.jsonl.gz",
		path,
	)
}

func TestObjectStoragePartitionPathEmptyPrefix(t *testing.T) {
	when := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	path := objectStoragePartitionPath("", "dbounce", "i-0", when, 1)
	assert.Equal(t,
		"year=2026/month=05/day=22/hour=00/dbounce-i-0-1.jsonl.gz",
		path,
	)
}

func TestDefaultObjectStorageInstanceIDIncludesProductAndPID(t *testing.T) {
	iid := defaultObjectStorageInstanceID("dbounce")
	assert.True(t, strings.HasPrefix(iid, "dbounce-"),
		"instance id should start with product name: %s", iid)
	// PID is the trailing dash-separated segment.
	parts := strings.Split(iid, "-")
	require.NotEmpty(t, parts)
	last := parts[len(parts)-1]
	assert.NotEmpty(t, last)
}

// ---------------------------------------------------------------------------
// Construction / refusal
// ---------------------------------------------------------------------------

func TestObjectStorageWriterRefusesEmptyEndpoint(t *testing.T) {
	_, err := NewObjectStorageWriter(ObjectStorageWriterOptions{
		EndpointURL: "", Bucket: "b", Product: "dbounce",
	})
	require.Error(t, err)
}

func TestObjectStorageWriterRefusesEmptyBucket(t *testing.T) {
	_, err := NewObjectStorageWriter(ObjectStorageWriterOptions{
		EndpointURL: "http://x", Bucket: "", Product: "dbounce",
	})
	require.Error(t, err)
}

func TestObjectStorageWriterRefusesEmptyProduct(t *testing.T) {
	_, err := NewObjectStorageWriter(ObjectStorageWriterOptions{
		EndpointURL: "http://x", Bucket: "b", Product: "",
	})
	require.Error(t, err)
}

func TestObjectStorageWriterDefaultsFillIn(t *testing.T) {
	w, err := NewObjectStorageWriter(ObjectStorageWriterOptions{
		EndpointURL: "http://x", Bucket: "b", Product: "dbounce",
	})
	require.NoError(t, err)
	assert.Equal(t, ObjectStorageDefaultRotationMinutes, w.rotationMinutes)
	assert.Equal(t, int64(ObjectStorageDefaultMaxSizeMB*1024*1024), w.maxSizeBytes)
	assert.Equal(t, ObjectStorageDefaultRegion, w.region)
	// Default instance id is auto-generated; not empty.
	assert.NotEmpty(t, w.instanceID)
}

// ---------------------------------------------------------------------------
// Happy path via mock S3
// ---------------------------------------------------------------------------

func newTestWriter(
	t *testing.T, stub *mockObjectStorageS3,
	rotationMinutes, maxSizeMB int,
	now time.Time,
) *ObjectStorageWriter {
	t.Helper()
	w, err := NewObjectStorageWriter(ObjectStorageWriterOptions{
		EndpointURL:     "https://s3.example.com",
		Bucket:          "bounce-audit-test",
		Prefix:          "test-suite",
		Region:          "us-east-1",
		Credentials:     ObjectStorageCredentials{AccessKeyID: "k", SecretAccessKey: "s"},
		Product:         "dbounce",
		InstanceID:      "test-host-1",
		RotationMinutes: rotationMinutes,
		MaxSizeMB:       maxSizeMB,
		S3Client:        stub,
		Now:             func() time.Time { return now },
	})
	require.NoError(t, err)
	return w
}

func TestStartProbesBucketViaHeadBucket(t *testing.T) {
	stub := &mockObjectStorageS3{}
	w := newTestWriter(t, stub, 5, 16,
		time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	ctx := context.Background()
	require.NoError(t, w.Start(ctx))
	defer w.Close()
	assert.Equal(t, 1, stub.HeadCalls(),
		"Start() should issue exactly one HeadBucket")
}

func TestStartBucketNotFoundReturnsError(t *testing.T) {
	stub := &mockObjectStorageS3{headErr: errors.New("NoSuchBucket")}
	w := newTestWriter(t, stub, 5, 16, time.Now().UTC())
	err := w.Start(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrObjectStorageBucketUnreachable)
}

func TestWriteBuffersUntilFlush(t *testing.T) {
	stub := &mockObjectStorageS3{}
	w := newTestWriter(t, stub, 5, 16,
		time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	ctx := context.Background()
	require.NoError(t, w.Start(ctx))
	defer w.Close()

	ev := Event{
		ClassUID:    6003,
		ActivityID:  4,
		ActivityName: "Delete",
	}
	w.Write(ctx, ev)
	// No upload yet — explicit flush triggers upload.
	assert.Empty(t, stub.Puts())
	w.Flush(ctx)
	puts := stub.Puts()
	require.Len(t, puts, 1)
	assert.Equal(t, "bounce-audit-test", puts[0].Bucket)
	// Key under the prefix + Hive partition layout.
	assert.True(t, strings.HasPrefix(puts[0].Key, "test-suite/year=2026/month=05/"),
		"key should start with prefix/year=YYYY/...; got %s", puts[0].Key)
	assert.True(t, strings.HasSuffix(puts[0].Key, ".jsonl.gz"),
		"key should end .jsonl.gz; got %s", puts[0].Key)
	assert.Contains(t, puts[0].Key, "dbounce-test-host-1-",
		"key should contain product-instance prefix; got %s", puts[0].Key)

	// Body is gzipped NDJSON.
	gz, err := gzip.NewReader(bytes.NewReader(puts[0].Body))
	require.NoError(t, err)
	decompressed, err := io.ReadAll(gz)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(decompressed), "\n"), "\n")
	require.Len(t, lines, 1)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &parsed))
	assert.Equal(t, float64(6003), parsed["class_uid"])
}

func TestWriteMultipleEventsOneFilePerFlush(t *testing.T) {
	stub := &mockObjectStorageS3{}
	w := newTestWriter(t, stub, 5, 16, time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	ctx := context.Background()
	require.NoError(t, w.Start(ctx))
	defer w.Close()

	for i := 0; i < 10; i++ {
		w.Write(ctx, Event{ClassUID: 6003, ActivityID: i})
	}
	w.Flush(ctx)
	puts := stub.Puts()
	require.Len(t, puts, 1)
	gz, err := gzip.NewReader(bytes.NewReader(puts[0].Body))
	require.NoError(t, err)
	decompressed, err := io.ReadAll(gz)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(decompressed), "\n"), "\n")
	assert.Len(t, lines, 10)
}

func TestStatusSurfacesCountsAndConfig(t *testing.T) {
	stub := &mockObjectStorageS3{}
	w := newTestWriter(t, stub, 5, 16, time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	ctx := context.Background()
	require.NoError(t, w.Start(ctx))
	defer w.Close()

	w.Write(ctx, Event{ClassUID: 6003})
	w.Write(ctx, Event{ClassUID: 6003})
	s := w.Status()
	assert.True(t, s.Configured)
	assert.Equal(t, "bounce-audit-test", s.Bucket)
	assert.Equal(t, "test-suite", s.Prefix)
	assert.Equal(t, "us-east-1", s.Region)
	assert.Equal(t, "dbounce", s.Product)
	assert.Equal(t, "test-host-1", s.InstanceID)
	assert.Equal(t, 5, s.RotationMinutes)
	assert.Equal(t, 16, s.MaxSizeMB)
	assert.Equal(t, 2, s.PendingRows)
	assert.Equal(t, int64(0), s.TotalFilesWritten)

	w.Flush(ctx)
	s = w.Status()
	assert.Equal(t, 0, s.PendingRows)
	assert.Equal(t, int64(1), s.TotalFilesWritten)
	assert.Equal(t, int64(2), s.TotalEvents)
	assert.Greater(t, s.TotalBytesWritten, int64(0))
	assert.True(t, s.WritesOK)
}

func TestSizeCapTriggersSynchronousFlush(t *testing.T) {
	stub := &mockObjectStorageS3{}
	w := newTestWriter(t, stub, 60, 1, // 1 MB cap so we cross it cheaply
		time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	ctx := context.Background()
	require.NoError(t, w.Start(ctx))
	defer w.Close()

	bigPayload := strings.Repeat("x", 200*1024)
	for i := 0; i < 6; i++ {
		w.Write(ctx, Event{
			ClassUID:     6003,
			ActivityID:   i,
			StatusDetail: bigPayload,
		})
	}
	puts := stub.Puts()
	assert.NotEmpty(t, puts, "size cap should have triggered at least one flush")
}

func TestWriterDropsWhenPendingBufferFull(t *testing.T) {
	stub := &mockObjectStorageS3{}
	// 3 pending rows max; 1024 MB max-size keeps the size cap from
	// masking the drop test.
	w, err := NewObjectStorageWriter(ObjectStorageWriterOptions{
		EndpointURL:     "https://s3.example.com",
		Bucket:          "bounce-audit-test",
		Prefix:          "t",
		Region:          "us-east-1",
		Credentials:     ObjectStorageCredentials{AccessKeyID: "k", SecretAccessKey: "s"},
		Product:         "dbounce",
		InstanceID:      "i",
		RotationMinutes: 60,
		MaxSizeMB:       1024,
		MaxPendingRows:  3,
		S3Client:        stub,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))
	defer w.Close()
	for i := 0; i < 5; i++ {
		w.Write(context.Background(), Event{ClassUID: 6003, ActivityID: i})
	}
	s := w.Status()
	assert.Equal(t, 3, s.PendingRows)
	assert.Equal(t, int64(2), s.DroppedEvents)
	assert.NotEmpty(t, s.LastError)
	assert.Contains(t, s.LastError, "buffer full")
}

func TestWriteBeforeStartIsNoop(t *testing.T) {
	stub := &mockObjectStorageS3{}
	w := newTestWriter(t, stub, 5, 16, time.Now().UTC())
	// No Start() call.
	w.Write(context.Background(), Event{ClassUID: 6003})
	assert.Empty(t, stub.Puts())
}

func TestCloseFlushesPendingSynchronously(t *testing.T) {
	stub := &mockObjectStorageS3{}
	w := newTestWriter(t, stub, 5, 16, time.Now().UTC())
	require.NoError(t, w.Start(context.Background()))
	for i := 0; i < 3; i++ {
		w.Write(context.Background(), Event{ClassUID: 6003, ActivityID: i})
	}
	assert.Empty(t, stub.Puts())
	w.Close()
	puts := stub.Puts()
	require.Len(t, puts, 1)
	gz, err := gzip.NewReader(bytes.NewReader(puts[0].Body))
	require.NoError(t, err)
	decompressed, err := io.ReadAll(gz)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(decompressed), "\n"), "\n")
	assert.Len(t, lines, 3)
}

func TestPutFailureRecordsLastError(t *testing.T) {
	stub := &mockObjectStorageS3{putErr: errors.New("upstream timeout")}
	w := newTestWriter(t, stub, 5, 16, time.Now().UTC())
	require.NoError(t, w.Start(context.Background()))
	defer w.Close()
	w.Write(context.Background(), Event{ClassUID: 6003})
	w.Flush(context.Background())
	s := w.Status()
	assert.False(t, s.WritesOK)
	assert.NotEmpty(t, s.LastError)
	assert.Contains(t, s.LastError, "put_object failed")
	assert.Equal(t, int64(0), s.TotalFilesWritten)
}

func TestRotationTimerTriggersFlush(t *testing.T) {
	stub := &mockObjectStorageS3{}
	// Use a clock that jumps forward so the rotator's overdue check
	// fires. RotationMinutes=5 means firstSeen+5min triggers a flush.
	baseNow := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	advancedNow := baseNow.Add(6 * time.Minute)
	var callCount int
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		callCount++
		if callCount <= 2 {
			return baseNow
		}
		return advancedNow
	}
	w, err := NewObjectStorageWriter(ObjectStorageWriterOptions{
		EndpointURL:     "https://s3.example.com",
		Bucket:          "bounce-audit-test",
		Prefix:          "t",
		Region:          "us-east-1",
		Credentials:     ObjectStorageCredentials{AccessKeyID: "k", SecretAccessKey: "s"},
		Product:         "dbounce",
		InstanceID:      "i",
		RotationMinutes: 5,
		MaxSizeMB:       1024,
		S3Client:        stub,
		Now:             clock,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))
	defer w.Close()
	w.Write(context.Background(), Event{ClassUID: 6003, ActivityID: 1})
	// Wait for the rotator's 1s tick to wake at least once.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(stub.Puts()) >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	assert.GreaterOrEqual(t, len(stub.Puts()), 1,
		"rotation timer should have triggered a flush")
}
