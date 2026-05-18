// Package audit — AWS Security Lake adapter (#258).
//
// Writes OCSF v1.1.0 class 6003 events as parquet files into a
// Security-Lake-compatible S3 bucket layout::
//
//	s3://<bucket>/region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/
//	    api_activity-<unix-ms>.parquet
//
// Rotation: in-memory batch per OCSF class flushed every
// rotation_seconds (default 300 = 5min) OR when batch bytes cross
// 10 MiB, whichever fires first. On Close() every pending batch is
// flushed synchronously so a clean restart doesn't drop events.
//
// Auth: STS AssumeRole when RoleARN is set; otherwise the default
// aws-sdk-go-v2 credential chain. Refuses to start without
// credentials so the operator finds the misconfiguration immediately.
//
// Per [[no-hosted-saas]] + [[self-host-zero-billing-dependency]]:
// the bucket lives in the operator's AWS account. iam-jit-the-
// company never receives the data.
//
// Per [[creates-never-mutates]]: every S3 operation is PutObject
// only. Rotation timestamps ensure unique keys so we never
// overwrite or delete.
//
// Per [[cross-product-agent-parity]]: same column set + partition
// layout as ibounce (Python) + kbounce (Go).
//
// Per [[security-team-positioning-safety-not-surveillance]]: the
// adapter is a passive sink. No "violation"/"infraction"/
// "unauthorized" language anywhere in operator-facing strings.

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/parquet-go/parquet-go"
)

// Spec defaults.
const (
	SecurityLakeDefaultRotationSeconds = 300
	SecurityLakeDefaultMaxBatchBytes   = 10 * 1024 * 1024
	SecurityLakeDefaultMaxPendingRows  = 100_000
)

// SecurityLakeRow is the canonical flattened OCSF v1.1.0 class 6003
// row shape written to every parquet file. Dot-paths in the source
// event become underscore-separated column names (matches AWS Glue's
// auto-crawl convention + Athena's idiomatic flat-column shape).
//
// Cross-product invariant: ibounce (Python) + kbounce (Go) ship the
// same column set in the same order. A single Athena query walks
// every product's partitions without per-product mapping.
//
// JSON-encoded columns (ResourcesJSON, UnmappedIAMJITExtJSON,
// UnmappedIAMJITAgentJSON) keep the Athena-side schema flat while
// preserving the nested OCSF substructure (use json_extract in
// Athena queries).
type SecurityLakeRow struct {
	MetadataVersion           string `parquet:"metadata_version,optional"`
	MetadataProductName       string `parquet:"metadata_product_name,optional"`
	MetadataProductVendorName string `parquet:"metadata_product_vendor_name,optional"`
	MetadataProductVersion    string `parquet:"metadata_product_version,optional"`
	Time                      int64  `parquet:"time,optional"`
	ClassUID                  int32  `parquet:"class_uid,optional"`
	ClassName                 string `parquet:"class_name,optional"`
	CategoryUID               int32  `parquet:"category_uid,optional"`
	CategoryName              string `parquet:"category_name,optional"`
	ActivityID                int32  `parquet:"activity_id,optional"`
	ActivityName              string `parquet:"activity_name,optional"`
	TypeUID                   int32  `parquet:"type_uid,optional"`
	TypeName                  string `parquet:"type_name,optional"`
	SeverityID                int32  `parquet:"severity_id,optional"`
	Severity                  string `parquet:"severity,optional"`
	StatusID                  int32  `parquet:"status_id,optional"`
	Status                    string `parquet:"status,optional"`
	StatusDetail              string `parquet:"status_detail,optional"`
	ActorUserName             string `parquet:"actor_user_name,optional"`
	ActorUserUID              string `parquet:"actor_user_uid,optional"`
	ActorSessionUID           string `parquet:"actor_session_uid,optional"`
	APIOperation              string `parquet:"api_operation,optional"`
	APIServiceName            string `parquet:"api_service_name,optional"`
	APIRequestUID             string `parquet:"api_request_uid,optional"`
	ResourcesJSON             string `parquet:"resources_json,optional"`
	SrcEndpointHostname       string `parquet:"src_endpoint_hostname,optional"`
	SrcEndpointIP             string `parquet:"src_endpoint_ip,optional"`
	SrcEndpointPort           int32  `parquet:"src_endpoint_port,optional"`
	DstEndpointHostname       string `parquet:"dst_endpoint_hostname,optional"`
	DstEndpointIP             string `parquet:"dst_endpoint_ip,optional"`
	DstEndpointPort           int32  `parquet:"dst_endpoint_port,optional"`
	UnmappedIAMJITMode        string `parquet:"unmapped_iam_jit_mode,optional"`
	UnmappedIAMJITProfile     string `parquet:"unmapped_iam_jit_profile,optional"`
	UnmappedIAMJITVerdict     string `parquet:"unmapped_iam_jit_verdict,optional"`
	UnmappedIAMJITDecisionID  int64  `parquet:"unmapped_iam_jit_decision_id,optional"`
	UnmappedIAMJITEnforced    bool   `parquet:"unmapped_iam_jit_enforced,optional"`
	UnmappedIAMJITEventType   string `parquet:"unmapped_iam_jit_event_type,optional"`
	UnmappedIAMJITExtJSON     string `parquet:"unmapped_iam_jit_ext_json,optional"`
	UnmappedIAMJITAgentJSON   string `parquet:"unmapped_iam_jit_agent_json,optional"`
}

// SecurityLakeColumnNames returns the canonical column-name order for
// the OCSF v1.1.0 class 6003 parquet schema. Cross-product test
// fixtures (ibounce + kbounce) compare against this list verbatim so
// a stray addition in any one product fails the test until all three
// are updated together.
var SecurityLakeColumnNames = []string{
	"metadata_version",
	"metadata_product_name",
	"metadata_product_vendor_name",
	"metadata_product_version",
	"time",
	"class_uid",
	"class_name",
	"category_uid",
	"category_name",
	"activity_id",
	"activity_name",
	"type_uid",
	"type_name",
	"severity_id",
	"severity",
	"status_id",
	"status",
	"status_detail",
	"actor_user_name",
	"actor_user_uid",
	"actor_session_uid",
	"api_operation",
	"api_service_name",
	"api_request_uid",
	"resources_json",
	"src_endpoint_hostname",
	"src_endpoint_ip",
	"src_endpoint_port",
	"dst_endpoint_hostname",
	"dst_endpoint_ip",
	"dst_endpoint_port",
	"unmapped_iam_jit_mode",
	"unmapped_iam_jit_profile",
	"unmapped_iam_jit_verdict",
	"unmapped_iam_jit_decision_id",
	"unmapped_iam_jit_enforced",
	"unmapped_iam_jit_event_type",
	"unmapped_iam_jit_ext_json",
	"unmapped_iam_jit_agent_json",
}

// Per-OCSF-class S3 file-prefix. Today every event the Bounce suite
// emits is class 6003 (API Activity). When a future slice adds
// another class, the rotator opens a separate batch keyed on the
// class_uid and this table grows.
var securityLakeClassPrefix = map[int32]string{
	6003: "api_activity",
}

func securityLakeClassPrefixFor(classUID int32) string {
	if p, ok := securityLakeClassPrefix[classUID]; ok {
		return p
	}
	return fmt.Sprintf("class-%d", classUID)
}

// SecurityLakeWriterOptions configures a SecurityLakeWriter.
type SecurityLakeWriterOptions struct {
	Bucket          string
	Region          string
	RoleARN         string
	RotationSeconds int
	MaxBatchBytes   int
	MaxPendingRows  int
	// S3Client lets tests inject a mock; production callers leave nil
	// and Start() constructs a real *s3.Client from the credential
	// chain (or AssumeRole when RoleARN is set).
	S3Client SecurityLakeS3Client
	// Now lets tests freeze the wall clock. Defaults to time.Now().UTC().
	Now func() time.Time
	// AccountID + CallerARN override the sts:GetCallerIdentity probe
	// for tests. Production callers leave both empty.
	AccountID string
	CallerARN string
}

// SecurityLakeS3Client is the minimal S3 surface the writer uses.
type SecurityLakeS3Client interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput,
		optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// SecurityLakeWriter is the audit-export Security Lake adapter (#258).
// Per-class in-memory batching; rotation on time OR size cap.
type SecurityLakeWriter struct {
	bucket          string
	region          string
	roleARN         string
	rotationSeconds int
	maxBatchBytes   int
	maxPendingRows  int

	s3Client  SecurityLakeS3Client
	now       func() time.Time
	accountID string
	callerARN string

	mu             sync.Mutex
	batches        map[int32][]SecurityLakeRow
	batchFirstSeen map[int32]time.Time

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

// SecurityLakeStatus is the runtime snapshot surfaced via the MCP
// status tool + the ExporterStatus aggregate.
type SecurityLakeStatus struct {
	Configured        bool   `json:"configured"`
	Bucket            string `json:"bucket,omitempty"`
	Region            string `json:"region,omitempty"`
	RoleARN           string `json:"role_arn,omitempty"`
	AccountID         string `json:"account_id,omitempty"`
	CallerARN         string `json:"caller_arn,omitempty"`
	RotationSeconds   int    `json:"rotation_seconds,omitempty"`
	MaxBatchBytes     int    `json:"max_batch_bytes,omitempty"`
	TotalEvents       int64  `json:"total_events"`
	TotalFilesWritten int64  `json:"total_files_written"`
	TotalBytesWritten int64  `json:"total_bytes_written"`
	DroppedEvents     int64  `json:"dropped_events"`
	PendingRows       int    `json:"pending_rows"`
	LastError         string `json:"last_error,omitempty"`
	LastErrorAtUnix   int64  `json:"last_error_at_unix,omitempty"`
	WritesOK          bool   `json:"writes_ok"`
}

// ErrSecurityLakeNoCredentials is returned when no AWS credentials are
// reachable at Start() time.
var ErrSecurityLakeNoCredentials = errors.New(
	"security-lake: no AWS credentials reachable " +
		"(default chain + AssumeRole both failed)")

// NewSecurityLakeWriter constructs the writer. Caller must call
// Start() before the first Write().
func NewSecurityLakeWriter(opts SecurityLakeWriterOptions) (*SecurityLakeWriter, error) {
	if opts.Bucket == "" {
		return nil, errors.New("security-lake: Bucket is required")
	}
	if opts.Region == "" {
		return nil, errors.New("security-lake: Region is required")
	}
	if opts.RotationSeconds <= 0 {
		opts.RotationSeconds = SecurityLakeDefaultRotationSeconds
	}
	if opts.MaxBatchBytes <= 0 {
		opts.MaxBatchBytes = SecurityLakeDefaultMaxBatchBytes
	}
	if opts.MaxPendingRows <= 0 {
		opts.MaxPendingRows = SecurityLakeDefaultMaxPendingRows
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	w := &SecurityLakeWriter{
		bucket:          opts.Bucket,
		region:          opts.Region,
		roleARN:         opts.RoleARN,
		rotationSeconds: opts.RotationSeconds,
		maxBatchBytes:   opts.MaxBatchBytes,
		maxPendingRows:  opts.MaxPendingRows,
		s3Client:        opts.S3Client,
		now:             opts.Now,
		accountID:       opts.AccountID,
		callerARN:       opts.CallerARN,
		batches:         make(map[int32][]SecurityLakeRow),
		batchFirstSeen:  make(map[int32]time.Time),
	}
	w.lastError.Store("")
	w.writesOK.Store(true)
	return w, nil
}

// Start probes credentials, constructs the S3 client (when one wasn't
// injected for tests), and spawns the rotation ticker. Idempotent.
func (w *SecurityLakeWriter) Start(ctx context.Context) error {
	w.startedMu.Lock()
	defer w.startedMu.Unlock()
	if w.started {
		return nil
	}
	if w.s3Client == nil {
		client, accountID, callerARN, err := buildSecurityLakeS3Client(
			ctx, w.region, w.roleARN,
		)
		if err != nil {
			return err
		}
		w.s3Client = client
		if w.accountID == "" {
			w.accountID = accountID
		}
		if w.callerARN == "" {
			w.callerARN = callerARN
		}
	}
	tickCtx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.tickerWG.Add(1)
	go w.tickLoop(tickCtx)
	w.started = true
	return nil
}

// Close flushes every pending batch synchronously + stops the ticker.
// Idempotent.
func (w *SecurityLakeWriter) Close() {
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
	w.FlushAll(context.Background())
}

// Write appends one OCSF event to its class's in-memory batch. Never
// blocks. Never propagates errors.
func (w *SecurityLakeWriter) Write(ctx context.Context, ev Event) {
	w.startedMu.Lock()
	started := w.started
	w.startedMu.Unlock()
	if !started {
		return
	}
	classUID := int32(ev.ClassUID)
	row := securityLakeRowFromEvent(ev)

	w.mu.Lock()
	totalPending := 0
	for _, b := range w.batches {
		totalPending += len(b)
	}
	if totalPending >= w.maxPendingRows {
		w.droppedEvents.Add(1)
		w.lastError.Store(fmt.Sprintf(
			"security-lake batch full at %d rows; dropped event",
			w.maxPendingRows))
		w.mu.Unlock()
		return
	}
	w.batches[classUID] = append(w.batches[classUID], row)
	if _, ok := w.batchFirstSeen[classUID]; !ok {
		w.batchFirstSeen[classUID] = w.now()
	}
	shouldFlush := len(w.batches[classUID])*1024 >= w.maxBatchBytes
	w.mu.Unlock()
	if shouldFlush {
		w.flushClass(ctx, classUID)
	}
}

// FlushAll flushes every pending class's batch synchronously.
func (w *SecurityLakeWriter) FlushAll(ctx context.Context) {
	w.mu.Lock()
	classUIDs := make([]int32, 0, len(w.batches))
	for k := range w.batches {
		classUIDs = append(classUIDs, k)
	}
	w.mu.Unlock()
	sort.Slice(classUIDs, func(i, j int) bool { return classUIDs[i] < classUIDs[j] })
	for _, classUID := range classUIDs {
		w.flushClass(ctx, classUID)
	}
}

// Status snapshots the writer state.
func (w *SecurityLakeWriter) Status() SecurityLakeStatus {
	w.mu.Lock()
	pending := 0
	for _, b := range w.batches {
		pending += len(b)
	}
	w.mu.Unlock()
	lastErr, _ := w.lastError.Load().(string)
	return SecurityLakeStatus{
		Configured:        true,
		Bucket:            w.bucket,
		Region:            w.region,
		RoleARN:           w.roleARN,
		AccountID:         w.accountID,
		CallerARN:         w.callerARN,
		RotationSeconds:   w.rotationSeconds,
		MaxBatchBytes:     w.maxBatchBytes,
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

// AccountID returns the AWS account id detected at Start().
func (w *SecurityLakeWriter) AccountID() string { return w.accountID }

// CallerARN returns the IAM identity ARN detected at Start().
func (w *SecurityLakeWriter) CallerARN() string { return w.callerARN }

// ------------------------------------------------------------------
// Internals
// ------------------------------------------------------------------

func (w *SecurityLakeWriter) tickLoop(ctx context.Context) {
	defer w.tickerWG.Done()
	d := time.Second
	if time.Duration(w.rotationSeconds)*time.Second < d {
		d = time.Duration(w.rotationSeconds) * time.Second
	}
	ticker := time.NewTicker(d)
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

func (w *SecurityLakeWriter) flushOverdue(ctx context.Context) {
	now := w.now()
	w.mu.Lock()
	var overdue []int32
	for classUID, firstSeen := range w.batchFirstSeen {
		if now.Sub(firstSeen) >= time.Duration(w.rotationSeconds)*time.Second {
			overdue = append(overdue, classUID)
		}
	}
	w.mu.Unlock()
	sort.Slice(overdue, func(i, j int) bool { return overdue[i] < overdue[j] })
	for _, classUID := range overdue {
		w.flushClass(ctx, classUID)
	}
}

func (w *SecurityLakeWriter) flushClass(ctx context.Context, classUID int32) {
	w.mu.Lock()
	rows := w.batches[classUID]
	if len(rows) == 0 {
		delete(w.batchFirstSeen, classUID)
		w.mu.Unlock()
		return
	}
	rowsSnapshot := make([]SecurityLakeRow, len(rows))
	copy(rowsSnapshot, rows)
	w.mu.Unlock()

	payload, err := encodeSecurityLakeRows(rowsSnapshot)
	if err != nil {
		w.recordError(fmt.Sprintf("parquet encode failed: %v", err))
		return
	}
	now := w.now()
	unixMS := now.UnixMilli()
	key := securityLakePartitionPath(w.region, now, classUID, unixMS)
	_, err = w.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(w.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(payload),
		ContentType: aws.String("application/vnd.apache.parquet"),
	})
	if err != nil {
		w.recordError(fmt.Sprintf("s3 put_object failed: %v", err))
		return
	}
	w.mu.Lock()
	if len(w.batches[classUID]) <= len(rowsSnapshot) {
		delete(w.batches, classUID)
		delete(w.batchFirstSeen, classUID)
	} else {
		w.batches[classUID] = w.batches[classUID][len(rowsSnapshot):]
		w.batchFirstSeen[classUID] = now
	}
	w.mu.Unlock()
	w.totalEvents.Add(int64(len(rowsSnapshot)))
	w.totalFilesWritten.Add(1)
	w.totalBytesWritten.Add(int64(len(payload)))
	w.writesOK.Store(true)
}

func (w *SecurityLakeWriter) recordError(msg string) {
	w.lastError.Store(msg)
	w.lastErrorAtUnix.Store(time.Now().Unix())
	w.writesOK.Store(false)
}

// securityLakePartitionPath returns the canonical S3 key for one
// parquet file.
func securityLakePartitionPath(region string, when time.Time, classUID int32, unixMS int64) string {
	return fmt.Sprintf(
		"region=%s/eventday=%s/eventhour=%s/%s-%d.parquet",
		region,
		when.UTC().Format("20060102"),
		when.UTC().Format("15"),
		securityLakeClassPrefixFor(classUID),
		unixMS,
	)
}

// encodeSecurityLakeRows serialises rows into an in-memory parquet
// file matching the canonical OCSF schema.
func encodeSecurityLakeRows(rows []SecurityLakeRow) ([]byte, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	writer := parquet.NewGenericWriter[SecurityLakeRow](
		&buf,
		parquet.Compression(&parquet.Snappy),
	)
	if _, err := writer.Write(rows); err != nil {
		return nil, fmt.Errorf("parquet write rows: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("parquet writer close: %w", err)
	}
	return buf.Bytes(), nil
}

// securityLakeRowFromEvent flattens an OCSF Event into the canonical
// row shape. Pointer fields (Actor / SrcEndpoint / DstEndpoint /
// Unmapped) are nil-checked; missing nested fields land as Go zero
// values which parquet renders as nulls thanks to the `optional`
// struct tags.
func securityLakeRowFromEvent(ev Event) SecurityLakeRow {
	row := SecurityLakeRow{
		MetadataVersion:           ev.Metadata.Version,
		MetadataProductName:       ev.Metadata.Product.Name,
		MetadataProductVendorName: ev.Metadata.Product.VendorName,
		MetadataProductVersion:    ev.Metadata.Product.Version,
		Time:                      ev.Time,
		ClassUID:                  int32(ev.ClassUID),
		ClassName:                 ev.ClassName,
		CategoryUID:               int32(ev.CategoryUID),
		CategoryName:              ev.CategoryName,
		ActivityID:                int32(ev.ActivityID),
		ActivityName:              ev.ActivityName,
		TypeUID:                   int32(ev.TypeUID),
		TypeName:                  ev.TypeName,
		SeverityID:                int32(ev.SeverityID),
		Severity:                  ev.Severity,
		StatusID:                  int32(ev.StatusID),
		Status:                    ev.Status,
		StatusDetail:              ev.StatusDetail,
		APIOperation:              ev.API.Operation,
		APIServiceName:            ev.API.Service.Name,
	}
	if ev.API.Request != nil {
		row.APIRequestUID = ev.API.Request.UID
	}
	if ev.Actor != nil {
		if ev.Actor.User != nil {
			row.ActorUserName = ev.Actor.User.Name
			row.ActorUserUID = ev.Actor.User.UID
		}
		if ev.Actor.Session != nil {
			row.ActorSessionUID = ev.Actor.Session.UID
		}
	}
	if ev.SrcEndpoint != nil {
		row.SrcEndpointHostname = ev.SrcEndpoint.Hostname
		row.SrcEndpointIP = ev.SrcEndpoint.IP
		row.SrcEndpointPort = int32(ev.SrcEndpoint.Port)
	}
	if ev.DstEndpoint != nil {
		row.DstEndpointHostname = ev.DstEndpoint.Hostname
		row.DstEndpointIP = ev.DstEndpoint.IP
		row.DstEndpointPort = int32(ev.DstEndpoint.Port)
	}
	// Resources: JSON-encode the slice. Defensive: a marshal failure
	// falls back to an empty array rather than dropping the whole event.
	if b, err := json.Marshal(ev.Resources); err == nil {
		row.ResourcesJSON = string(b)
	} else {
		row.ResourcesJSON = "[]"
	}
	if ev.Unmapped != nil {
		row.UnmappedIAMJITMode = ev.Unmapped.IAMJIT.Mode
		row.UnmappedIAMJITProfile = ev.Unmapped.IAMJIT.Profile
		row.UnmappedIAMJITVerdict = ev.Unmapped.IAMJIT.Verdict
		row.UnmappedIAMJITDecisionID = ev.Unmapped.IAMJIT.DecisionID
		row.UnmappedIAMJITEnforced = ev.Unmapped.IAMJIT.Enforced
		if ev.Unmapped.IAMJIT.Ext != nil {
			if b, err := json.Marshal(ev.Unmapped.IAMJIT.Ext); err == nil {
				row.UnmappedIAMJITExtJSON = string(b)
			} else {
				row.UnmappedIAMJITExtJSON = "{}"
			}
		} else {
			row.UnmappedIAMJITExtJSON = "{}"
		}
		if ev.Unmapped.IAMJIT.Agent != nil {
			if b, err := json.Marshal(ev.Unmapped.IAMJIT.Agent); err == nil {
				row.UnmappedIAMJITAgentJSON = string(b)
			}
		}
	} else {
		row.UnmappedIAMJITExtJSON = "{}"
	}
	return row
}

// buildSecurityLakeS3Client returns an S3 client + (accountID,
// callerARN) for the startup banner. Returns
// ErrSecurityLakeNoCredentials when no usable credentials are
// reachable.
func buildSecurityLakeS3Client(
	ctx context.Context, region, roleARN string,
) (*s3.Client, string, string, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region))
	if err != nil {
		return nil, "", "", fmt.Errorf(
			"security-lake: load default AWS config: %w", err)
	}
	if roleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN,
			func(o *stscreds.AssumeRoleOptions) {
				o.RoleSessionName = "dbounce-security-lake"
			})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	stsClient := sts.NewFromConfig(cfg)
	ident, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: %v",
			ErrSecurityLakeNoCredentials, err)
	}
	accountID := ""
	callerARN := ""
	if ident.Account != nil {
		accountID = *ident.Account
	}
	if ident.Arn != nil {
		callerARN = *ident.Arn
	}
	client := s3.NewFromConfig(cfg)
	return client, accountID, callerARN, nil
}
