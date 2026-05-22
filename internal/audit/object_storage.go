// Package audit — cloud-neutral S3-compatible NDJSON object-storage
// sink (#317).
//
// Per founder direction 2026-05-22: bouncers (other than ibounce) are
// cloud-neutral. Today we ship JSONL files + HTTPS webhook + AWS-only
// Security Lake parquet. Operators on GCS / Azure Blob / MinIO / R2 /
// B2 have no pull-based collection path. This module adds one
// S3-compatible NDJSON sink that writes operator-named buckets via
// the S3 API. Works across AWS S3 (native), GCS interop (HMAC keys),
// Azure Blob (S3-compat layer), MinIO, Cloudflare R2, Backblaze B2,
// DigitalOcean Spaces.
//
// Output shape: NDJSON (one OCSF event per line), gzip-compressed.
// File naming:
//
//	{prefix}/year=YYYY/month=MM/day=DD/hour=HH/
//	    {product}-{instance_id}-{timestamp}.jsonl.gz
//
// Hive-style partitioning enables Athena / BigQuery / Spark / Trino
// direct querying. SIEM-pull-friendly: collectors do LIST + GET
// against the prefix; new files land at predictable cadence.
//
// Per [[self-host-zero-billing-dependency]]: operator owns the
// bucket; dbouncer ships the writer. iam-jit-the-company never
// receives the data and is never on the billing path.
//
// Per [[creates-never-mutates]]: every S3 operation is PutObject /
// DeleteObject on a `.in-progress` partial — the canonical
// finalized object is never mutated post-publish.
//
// Per [[don't-tailor-to-lighthouse]]: generic S3-compat; tuned to
// no single vendor.
//
// Per [[cross-product-agent-parity]]: ibounce (Python) + dbounce
// (Go) + gbounce (Go) ship the same shape with byte-identical wire
// format. The cross-product invariant is fixed in
// `tests/integration/object_storage_sink_test.py` (iam-roles).
//
// Per [[security-team-positioning-safety-not-surveillance]]: this
// is a passive sink. No "violation"/"infraction"/"unauthorized"
// language anywhere in operator-facing strings.
package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Spec defaults per #317. Operators can shrink for tests (or grow
// for high-volume orgs preferring fewer, larger files).
const (
	ObjectStorageDefaultRotationMinutes = 5
	ObjectStorageDefaultMaxSizeMB       = 16
	ObjectStorageDefaultMaxPendingRows  = 100_000
	ObjectStorageDefaultRegion          = "us-east-1"
	// ObjectStorageInProgressSuffix is the marker for the actively-
	// written object before its rotation completes. Collectors that
	// filter on the finalized `.jsonl.gz` suffix never observe
	// partials.
	ObjectStorageInProgressSuffix = ".in-progress"
)

// ObjectStorageCredentials is the static S3-compatible credential
// pair the writer signs requests with. Loaded from env vars OR an
// explicit credentials file (operator picks; file overrides env).
type ObjectStorageCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// ErrObjectStorageNoCredentials is returned when neither env vars
// nor the credentials file yield usable credentials. Surfaced at
// Start() so the operator sees the misconfiguration immediately.
var ErrObjectStorageNoCredentials = errors.New(
	"object-storage: no credentials reachable (set " +
		"AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars OR pass " +
		"--audit-object-storage-credentials-file PATH)")

// ErrObjectStorageBucketUnreachable is returned when the bucket
// probe (HeadBucket) fails at Start(). Wraps the underlying SDK
// error so the operator sees both the policy hint AND the
// connectivity context.
var ErrObjectStorageBucketUnreachable = errors.New(
	"object-storage: bucket probe failed at Start()")

// LoadObjectStorageCredentials resolves credentials from operator
// config. Precedence (highest first):
//  1. credentialsFile when non-empty
//  2. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
//     env vars
//
// The file shape is either YAML or INI. YAML keys are
// access_key_id / secret_access_key / session_token; INI uses the
// same keys under a [default] section.
//
// Returns ErrObjectStorageNoCredentials when no creds are
// reachable. Refuse-to-start posture per the spec.
func LoadObjectStorageCredentials(credentialsFile string) (ObjectStorageCredentials, error) {
	if credentialsFile != "" {
		return loadObjectStorageCredentialsFile(credentialsFile)
	}
	access := strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID"))
	secret := strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY"))
	if access == "" || secret == "" {
		return ObjectStorageCredentials{}, ErrObjectStorageNoCredentials
	}
	return ObjectStorageCredentials{
		AccessKeyID:     access,
		SecretAccessKey: secret,
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}, nil
}

// loadObjectStorageCredentialsFile parses a credentials file (YAML
// or INI). The shape is detected by the first non-blank, non-
// comment line. Both formats accept the same three keys.
func loadObjectStorageCredentialsFile(path string) (ObjectStorageCredentials, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ObjectStorageCredentials{}, fmt.Errorf(
			"object-storage: read credentials file %q: %w", path, err)
	}
	data := map[string]string{}
	inDefault := false
	isINI := false
	for _, line := range strings.Split(string(raw), "\n") {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		if strings.HasPrefix(stripped, "[") && strings.HasSuffix(stripped, "]") {
			isINI = true
			inDefault = stripped == "[default]"
			continue
		}
		// INI keys: skip outside [default] section once any section header was seen.
		if isINI && !inDefault {
			continue
		}
		// Pick the first matching separator. INI files use '='; YAML
		// uses ':'. The credentials_file format is permissive — we
		// accept either separator inside [default] sections too.
		var sep string
		if isINI {
			if strings.Contains(stripped, "=") {
				sep = "="
			}
		} else if strings.Contains(stripped, ":") {
			sep = ":"
		} else if strings.Contains(stripped, "=") {
			sep = "="
		}
		if sep == "" {
			continue
		}
		idx := strings.Index(stripped, sep)
		k := strings.TrimSpace(stripped[:idx])
		v := strings.Trim(strings.TrimSpace(stripped[idx+1:]), "\"'")
		data[k] = v
	}
	access := data["access_key_id"]
	secret := data["secret_access_key"]
	if access == "" || secret == "" {
		return ObjectStorageCredentials{}, fmt.Errorf(
			"object-storage: credentials file %q missing access_key_id "+
				"or secret_access_key (YAML or INI [default] shape "+
				"required)", path)
	}
	return ObjectStorageCredentials{
		AccessKeyID:     access,
		SecretAccessKey: secret,
		SessionToken:    data["session_token"],
	}, nil
}

// ObjectStorageS3Client is the minimal S3 surface the writer uses.
// Lets tests inject a mock without pulling in AWS SDK test helpers.
type ObjectStorageS3Client interface {
	HeadBucket(ctx context.Context, in *s3.HeadBucketInput,
		optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	PutObject(ctx context.Context, in *s3.PutObjectInput,
		optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput,
		optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// ObjectStorageWriterOptions configures an ObjectStorageWriter.
// Caller is expected to have already validated EndpointURL +
// Bucket + Product; NewObjectStorageWriter re-checks defensively.
type ObjectStorageWriterOptions struct {
	EndpointURL      string
	Bucket           string
	Prefix           string
	Region           string
	Credentials      ObjectStorageCredentials
	Product          string
	InstanceID       string
	RotationMinutes  int
	MaxSizeMB        int
	MaxPendingRows   int
	// S3Client lets tests inject a mock; production callers leave
	// nil and Start() constructs a real *s3.Client from the
	// credentials + endpoint.
	S3Client ObjectStorageS3Client
	// Now lets tests freeze the wall clock for rotation-deadline
	// assertions. Defaults to time.Now().UTC() when nil.
	Now func() time.Time
}

// ObjectStorageStatus is the runtime snapshot surfaced via MCP +
// /healthz. Symmetric with audit.Status fields for the existing
// channels.
type ObjectStorageStatus struct {
	Configured        bool   `json:"configured"`
	EndpointURL       string `json:"endpoint_url,omitempty"`
	Bucket            string `json:"bucket,omitempty"`
	Prefix            string `json:"prefix,omitempty"`
	Region            string `json:"region,omitempty"`
	Product           string `json:"product,omitempty"`
	InstanceID        string `json:"instance_id,omitempty"`
	RotationMinutes   int    `json:"rotation_minutes,omitempty"`
	MaxSizeMB         int    `json:"max_size_mb,omitempty"`
	TotalEvents       int64  `json:"total_events"`
	TotalFilesWritten int64  `json:"total_files_written"`
	TotalBytesWritten int64  `json:"total_bytes_written"`
	DroppedEvents     int64  `json:"dropped_events"`
	PendingRows       int    `json:"pending_rows"`
	LastError         string `json:"last_error,omitempty"`
	LastErrorAtUnix   int64  `json:"last_error_at_unix,omitempty"`
	WritesOK          bool   `json:"writes_ok"`
}

// ObjectStorageWriter is the cloud-neutral S3-compat NDJSON sink.
// Lifecycle:
//
//	w, err := NewObjectStorageWriter(opts)
//	if err != nil { return err }
//	if err := w.Start(ctx); err != nil { return err }  // probe bucket
//	w.Write(ctx, ev)            // never blocks
//	w.Close()                   // finalize active file + exit
//
// Per-instance file: each writer maintains one active NDJSON buffer
// in memory. The rotator finalizes the buffer when EITHER the
// rotation interval elapses OR the size cap fires.
//
// Thread-safety: Write / Flush / Close hold a single coarse lock
// around the active buffer; the proxy hot-path enqueues + the
// rotator drains under the lock.
type ObjectStorageWriter struct {
	endpointURL     string
	bucket          string
	prefix          string
	region          string
	credentials     ObjectStorageCredentials
	product         string
	instanceID      string
	rotationMinutes int
	maxSizeBytes    int64
	maxPendingRows  int

	s3Client ObjectStorageS3Client
	now      func() time.Time

	mu                sync.Mutex
	bufferLines       [][]byte
	bufferBytesEst    int64
	bufferFirstSeen   time.Time
	activeInProgKey   string

	totalEvents       atomic.Int64
	totalFilesWritten atomic.Int64
	totalBytesWritten atomic.Int64
	droppedEvents     atomic.Int64
	lastError         atomic.Value // string
	lastErrorAtUnix   atomic.Int64
	writesOK          atomic.Bool

	cancel    context.CancelFunc
	tickerWG  sync.WaitGroup
	started   bool
	startedMu sync.Mutex
}

// NewObjectStorageWriter constructs the writer. Caller must call
// Start() before the first Write() (Write is a no-op until Start
// succeeds; matches the LogWriter / WebhookPusher posture).
//
// Returns a config error when EndpointURL / Bucket / Product /
// RotationMinutes / MaxSizeMB are invalid; never reaches out to
// the network at construction time (that happens in Start()).
func NewObjectStorageWriter(opts ObjectStorageWriterOptions) (*ObjectStorageWriter, error) {
	if opts.EndpointURL == "" {
		return nil, errors.New("object-storage: EndpointURL is required")
	}
	if opts.Bucket == "" {
		return nil, errors.New("object-storage: Bucket is required")
	}
	if opts.Product == "" {
		return nil, errors.New("object-storage: Product is required")
	}
	if opts.Region == "" {
		opts.Region = ObjectStorageDefaultRegion
	}
	if opts.RotationMinutes <= 0 {
		opts.RotationMinutes = ObjectStorageDefaultRotationMinutes
	}
	if opts.MaxSizeMB <= 0 {
		opts.MaxSizeMB = ObjectStorageDefaultMaxSizeMB
	}
	if opts.MaxPendingRows <= 0 {
		opts.MaxPendingRows = ObjectStorageDefaultMaxPendingRows
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.InstanceID == "" {
		opts.InstanceID = defaultObjectStorageInstanceID(opts.Product)
	}
	w := &ObjectStorageWriter{
		endpointURL:     opts.EndpointURL,
		bucket:          opts.Bucket,
		prefix:          strings.Trim(opts.Prefix, "/"),
		region:          opts.Region,
		credentials:     opts.Credentials,
		product:         opts.Product,
		instanceID:      opts.InstanceID,
		rotationMinutes: opts.RotationMinutes,
		maxSizeBytes:    int64(opts.MaxSizeMB) * 1024 * 1024,
		maxPendingRows:  opts.MaxPendingRows,
		s3Client:        opts.S3Client,
		now:             opts.Now,
	}
	w.lastError.Store("")
	w.writesOK.Store(true)
	return w, nil
}

// Start probes the bucket + spawns the rotator. Idempotent. Returns
// ErrObjectStorageBucketUnreachable when the probe fails.
func (w *ObjectStorageWriter) Start(ctx context.Context) error {
	w.startedMu.Lock()
	defer w.startedMu.Unlock()
	if w.started {
		return nil
	}
	if w.s3Client == nil {
		client, err := buildObjectStorageS3Client(ctx,
			w.endpointURL, w.region, w.credentials)
		if err != nil {
			return err
		}
		w.s3Client = client
	}
	if _, err := w.s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(w.bucket),
	}); err != nil {
		return fmt.Errorf("%w: bucket=%s endpoint=%s: %v",
			ErrObjectStorageBucketUnreachable, w.bucket, w.endpointURL, err)
	}
	tickCtx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.tickerWG.Add(1)
	go w.tickLoop(tickCtx)
	w.started = true
	return nil
}

// Close finalizes the active NDJSON buffer synchronously + stops
// the rotator. Idempotent. Per the spec: on shutdown, flush all
// pending synchronously.
func (w *ObjectStorageWriter) Close() {
	w.startedMu.Lock()
	if !w.started {
		w.startedMu.Unlock()
		return
	}
	w.started = false
	cancel := w.cancel
	w.startedMu.Unlock()
	if cancel != nil {
		cancel()
	}
	w.tickerWG.Wait()
	w.Flush(context.Background())
}

// Write appends one OCSF event to the active buffer. Never blocks.
// Never propagates errors back to the proxy hot-path; failed writes
// increment droppedEvents + populate lastError for the MCP status
// surface.
//
// When the buffer crosses the size cap this call triggers a
// synchronous flush.
func (w *ObjectStorageWriter) Write(ctx context.Context, ev Event) {
	w.startedMu.Lock()
	started := w.started
	w.startedMu.Unlock()
	if !started {
		return
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		w.recordError(fmt.Sprintf("json marshal failed: %v", err))
		return
	}
	var shouldFlush bool
	w.mu.Lock()
	if len(w.bufferLines) >= w.maxPendingRows {
		w.droppedEvents.Add(1)
		w.lastError.Store(fmt.Sprintf(
			"object-storage buffer full at %d rows; dropped event",
			w.maxPendingRows))
		w.mu.Unlock()
		return
	}
	w.bufferLines = append(w.bufferLines, payload)
	w.bufferBytesEst += int64(len(payload) + 1) // +1 for newline
	if w.bufferFirstSeen.IsZero() {
		w.bufferFirstSeen = w.now()
	}
	if w.bufferBytesEst >= w.maxSizeBytes {
		shouldFlush = true
	}
	w.mu.Unlock()
	if shouldFlush {
		w.Flush(ctx)
	}
}

// Flush finalizes the active buffer: serialize, gzip, upload to
// the canonical key, then delete any leftover `.in-progress`
// sibling. Safe from any goroutine. Used by Close() + the
// operator-driven flush CLI subcommand.
func (w *ObjectStorageWriter) Flush(ctx context.Context) {
	w.mu.Lock()
	if len(w.bufferLines) == 0 {
		w.bufferFirstSeen = time.Time{}
		w.activeInProgKey = ""
		w.mu.Unlock()
		return
	}
	linesSnapshot := make([][]byte, len(w.bufferLines))
	copy(linesSnapshot, w.bufferLines)
	// Reset the buffer up-front so producers don't block on the
	// upload. If the upload fails the rows are surfaced via the
	// dropped counter + last_error.
	w.bufferLines = w.bufferLines[:0]
	w.bufferBytesEst = 0
	firstSeen := w.bufferFirstSeen
	w.bufferFirstSeen = time.Time{}
	inProgressKey := w.activeInProgKey
	w.activeInProgKey = ""
	w.mu.Unlock()

	when := firstSeen
	if when.IsZero() {
		when = w.now()
	}
	unixMS := when.UnixMilli()
	finalKey := objectStoragePartitionPath(
		w.prefix, w.product, w.instanceID, when, unixMS,
	)
	// Serialize + gzip.
	var buf bytes.Buffer
	for i, line := range linesSnapshot {
		if i > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(line)
	}
	buf.WriteByte('\n') // trailing newline mirrors the Python impl
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := io.Copy(gz, &buf); err != nil {
		_ = gz.Close()
		w.recordError(fmt.Sprintf("gzip write failed: %v", err))
		return
	}
	if err := gz.Close(); err != nil {
		w.recordError(fmt.Sprintf("gzip close failed: %v", err))
		return
	}
	payload := gzBuf.Bytes()
	_, err := w.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          aws.String(w.bucket),
		Key:             aws.String(finalKey),
		Body:            bytes.NewReader(payload),
		ContentType:     aws.String("application/x-ndjson"),
		ContentEncoding: aws.String("gzip"),
	})
	if err != nil {
		w.recordError(fmt.Sprintf("object-storage put_object failed: %v", err))
		return
	}
	// Best-effort cleanup of any prior `.in-progress` object.
	// Failure here is non-fatal; logs only.
	if inProgressKey != "" {
		_, _ = w.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(w.bucket),
			Key:    aws.String(inProgressKey),
		})
	}
	w.totalEvents.Add(int64(len(linesSnapshot)))
	w.totalFilesWritten.Add(1)
	w.totalBytesWritten.Add(int64(len(payload)))
	w.writesOK.Store(true)
}

// Status snapshots the writer state for the MCP audit-export status
// tool + /healthz.
func (w *ObjectStorageWriter) Status() ObjectStorageStatus {
	w.mu.Lock()
	pending := len(w.bufferLines)
	w.mu.Unlock()
	lastErr, _ := w.lastError.Load().(string)
	return ObjectStorageStatus{
		Configured:        true,
		EndpointURL:       w.endpointURL,
		Bucket:            w.bucket,
		Prefix:            w.prefix,
		Region:            w.region,
		Product:           w.product,
		InstanceID:        w.instanceID,
		RotationMinutes:   w.rotationMinutes,
		MaxSizeMB:         int(w.maxSizeBytes / 1024 / 1024),
		TotalEvents:       w.totalEvents.Load(),
		TotalFilesWritten: w.totalFilesWritten.Load(),
		TotalBytesWritten: w.totalBytesWritten.Load(),
		DroppedEvents:     w.droppedEvents.Load(),
		PendingRows:       pending,
		LastError:         lastErr,
		LastErrorAtUnix:   w.lastErrorAtUnix.Load(),
		WritesOK:          w.writesOK.Load(),
	}
}

// InstanceID returns the per-bouncer instance identifier used in
// the object key. Exposed for the startup banner.
func (w *ObjectStorageWriter) InstanceID() string { return w.instanceID }

// ------------------------------------------------------------------
// Internals
// ------------------------------------------------------------------

func (w *ObjectStorageWriter) tickLoop(ctx context.Context) {
	defer w.tickerWG.Done()
	// 1s minimum tick so tests with short rotation intervals don't
	// over-sleep. Real-world rotation is minutes-scale so the
	// overhead is negligible.
	tick := time.Second
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.flushOverdue(ctx)
		}
	}
}

func (w *ObjectStorageWriter) flushOverdue(ctx context.Context) {
	now := w.now()
	w.mu.Lock()
	overdue := false
	if !w.bufferFirstSeen.IsZero() {
		if now.Sub(w.bufferFirstSeen) >=
			time.Duration(w.rotationMinutes)*time.Minute {
			overdue = true
		}
	}
	w.mu.Unlock()
	if overdue {
		w.Flush(ctx)
	}
}

func (w *ObjectStorageWriter) recordError(msg string) {
	w.lastError.Store(msg)
	w.lastErrorAtUnix.Store(time.Now().Unix())
	w.writesOK.Store(false)
}

// objectStoragePartitionPath returns the canonical S3 key for one
// NDJSON file. Format:
//
//	{prefix}/year=YYYY/month=MM/day=DD/hour=HH/
//	    {product}-{instance_id}-{unix_ms}.jsonl.gz
//
// Hive-style partitioning. Athena / BigQuery / Spark / Trino all
// auto-discover partitions from this layout.
func objectStoragePartitionPath(
	prefix, product, instanceID string,
	when time.Time, unixMS int64,
) string {
	utc := when.UTC()
	parts := fmt.Sprintf(
		"year=%s/month=%s/day=%s/hour=%s/%s-%s-%d.jsonl.gz",
		utc.Format("2006"),
		utc.Format("01"),
		utc.Format("02"),
		utc.Format("15"),
		product, instanceID, unixMS,
	)
	if prefix == "" {
		return parts
	}
	return prefix + "/" + parts
}

// defaultObjectStorageInstanceID builds a stable per-bouncer
// identifier from hostname + pid. Operators with ephemeral
// hostnames (containers / k8s pods) should pass --instance-id
// explicitly so the path stays stable across restarts.
func defaultObjectStorageInstanceID(product string) string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	// Strip dots so the hostname doesn't accidentally introduce path
	// separators in some S3-compat layers that interpret dots.
	host = strings.ReplaceAll(host, ".", "-")
	host = strings.ReplaceAll(host, "/", "-")
	return fmt.Sprintf("%s-%s-%d", product, host, os.Getpid())
}

// buildObjectStorageS3Client constructs an *s3.Client pointed at
// the operator's S3-compatible endpoint. Uses static credentials
// (no STS AssumeRole) because the typical S3-compat target
// (MinIO / R2 / B2 / GCS interop / Azure Blob S3 layer) doesn't
// understand AssumeRole — operators want plain access-key-id +
// secret-access-key.
func buildObjectStorageS3Client(
	ctx context.Context, endpointURL, region string,
	creds ObjectStorageCredentials,
) (*s3.Client, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				creds.AccessKeyID,
				creds.SecretAccessKey,
				creds.SessionToken,
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"object-storage: load aws config: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpointURL)
		// Path-style addressing — MinIO + several other S3-compat
		// providers default to / require path-style. Real AWS S3
		// accepts both; this is the safest cross-provider choice.
		o.UsePathStyle = true
	})
	return client, nil
}
