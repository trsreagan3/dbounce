package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/parquet-go/parquet-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock S3 client
// ---------------------------------------------------------------------------

type mockS3PutObject struct {
	Bucket string
	Key    string
	Body   []byte
}

type mockS3Client struct {
	mu     sync.Mutex
	puts   []mockS3PutObject
	putErr error
}

func (m *mockS3Client) PutObject(
	ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	body := bytes.Buffer{}
	if in.Body != nil {
		body.ReadFrom(in.Body)
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

func (m *mockS3Client) Puts() []mockS3PutObject {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mockS3PutObject, len(m.puts))
	copy(out, m.puts)
	return out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func sampleDecisionEvent() Event {
	return Event{
		Metadata: Metadata{
			Version: "1.1.0",
			Product: Product_{
				Name:       "dbounce",
				VendorName: "iam-jit",
				Version:    "dev",
			},
		},
		Time:         time.Now().UnixMilli(),
		ClassUID:     6003,
		ClassName:    "API Activity",
		CategoryUID:  6,
		CategoryName: "Application Activity",
		ActivityID:   2,
		ActivityName: "select",
		TypeUID:      600302,
		TypeName:     "API Activity: Read",
		SeverityID:   1,
		Severity:     "Informational",
		StatusID:     1,
		Status:       "Success",
		StatusDetail: "",
		Actor: &Actor{
			User: &User{Name: "agent@example.com", UID: "agent@example.com"},
		},
		API: API{
			Operation: "select",
			Service:   Service{Name: "postgresql"},
			Request:   &Request{UID: "42"},
		},
		Resources: []Resource{
			{Name: "public.users", UID: "public.users", Type: "sql table"},
		},
		Unmapped: &Unmapped{IAMJIT: IAMJITExt{
			Mode:       "transparent",
			Profile:    "safe-default",
			Verdict:    "allow",
			DecisionID: 42,
			Enforced:   true,
			Ext: map[string]any{
				"dialect": "postgresql",
				"is_dml":  false,
			},
		}},
	}
}

// ---------------------------------------------------------------------------
// Schema + helpers
// ---------------------------------------------------------------------------

func TestSecurityLakeColumnNamesAreLockedIn(t *testing.T) {
	// Cross-product contract per [[cross-product-agent-parity]]: the
	// column set + order are byte-stable. ibounce + kbounce assert
	// the same list in their own tests.
	require.Equal(t, "metadata_version", SecurityLakeColumnNames[0])
	require.Contains(t, SecurityLakeColumnNames, "class_uid")
	require.Contains(t, SecurityLakeColumnNames, "activity_id")
	require.Contains(t, SecurityLakeColumnNames, "unmapped_iam_jit_verdict")
	require.Contains(t, SecurityLakeColumnNames, "unmapped_iam_jit_decision_id")
	require.Contains(t, SecurityLakeColumnNames, "unmapped_iam_jit_ext_json")
	require.Contains(t, SecurityLakeColumnNames, "resources_json")
	// Lock the count so a stray addition fails the test (forces the
	// author to update ibounce + kbounce together).
	require.Equal(t, 39, len(SecurityLakeColumnNames),
		"cross-product invariant: 39 columns; update ibounce + kbounce + this test together")
}

func TestSecurityLakePartitionPath(t *testing.T) {
	when := time.Date(2026, 5, 19, 14, 7, 33, 0, time.UTC)
	got := securityLakePartitionPath("us-east-1", when, 6003, 1747667253000)
	require.Equal(t,
		"region=us-east-1/eventday=20260519/eventhour=14/api_activity-1747667253000.parquet",
		got)
}

func TestSecurityLakePartitionPathUnknownClassFallback(t *testing.T) {
	when := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)
	got := securityLakePartitionPath("us-west-2", when, 7777, 123)
	require.Equal(t,
		"region=us-west-2/eventday=20260519/eventhour=14/class-7777-123.parquet",
		got)
}

func TestSecurityLakePartitionPathTwoDigitHour(t *testing.T) {
	when := time.Date(2026, 5, 19, 4, 0, 0, 0, time.UTC)
	got := securityLakePartitionPath("eu-west-1", when, 6003, 1)
	require.Equal(t,
		"region=eu-west-1/eventday=20260519/eventhour=04/api_activity-1.parquet",
		got, fmt.Sprintf("got=%s", got))
}

func TestSecurityLakeRowFromEvent(t *testing.T) {
	ev := sampleDecisionEvent()
	row := securityLakeRowFromEvent(ev)
	require.Equal(t, "1.1.0", row.MetadataVersion)
	require.Equal(t, "dbounce", row.MetadataProductName)
	require.Equal(t, "iam-jit", row.MetadataProductVendorName)
	require.Equal(t, int32(6003), row.ClassUID)
	require.Equal(t, "allow", row.UnmappedIAMJITVerdict)
	require.Equal(t, int64(42), row.UnmappedIAMJITDecisionID)
	require.True(t, row.UnmappedIAMJITEnforced)
	require.Equal(t, "agent@example.com", row.ActorUserName)
	require.Equal(t, "select", row.APIOperation)
	require.Equal(t, "postgresql", row.APIServiceName)
	require.Equal(t, "42", row.APIRequestUID)
	require.NotEmpty(t, row.ResourcesJSON)
	require.NotEmpty(t, row.UnmappedIAMJITExtJSON)
}

func TestEncodeSecurityLakeRowsRoundTrip(t *testing.T) {
	row1 := securityLakeRowFromEvent(sampleDecisionEvent())
	row2 := securityLakeRowFromEvent(sampleDecisionEvent())
	row2.UnmappedIAMJITDecisionID = 43
	row2.UnmappedIAMJITVerdict = "deny"
	payload, err := encodeSecurityLakeRows([]SecurityLakeRow{row1, row2})
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	reader := parquet.NewGenericReader[SecurityLakeRow](bytes.NewReader(payload))
	got := make([]SecurityLakeRow, 2)
	n, err := reader.Read(got)
	require.Equal(t, 2, n)
	if err != nil {
		// EOF is expected when all rows are drained (mirrors io.Reader).
		require.ErrorIs(t, err, io.EOF)
	}
	require.Equal(t, "allow", got[0].UnmappedIAMJITVerdict)
	require.Equal(t, int64(42), got[0].UnmappedIAMJITDecisionID)
	require.Equal(t, "deny", got[1].UnmappedIAMJITVerdict)

	// Schema verification: every canonical column is present.
	schema := reader.Schema()
	got_names := make(map[string]bool)
	for _, f := range schema.Fields() {
		got_names[f.Name()] = true
	}
	for _, name := range SecurityLakeColumnNames {
		require.True(t, got_names[name],
			"column %q missing from parquet schema", name)
	}
}

// ---------------------------------------------------------------------------
// Construction / refusal-to-start
// ---------------------------------------------------------------------------

func TestNewSecurityLakeWriterRequiresBucket(t *testing.T) {
	_, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "", Region: "us-east-1",
	})
	require.Error(t, err)
}

func TestNewSecurityLakeWriterRequiresRegion(t *testing.T) {
	_, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "b", Region: "",
	})
	require.Error(t, err)
}

func TestNewSecurityLakeWriterAppliesDefaults(t *testing.T) {
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "b", Region: "r",
	})
	require.NoError(t, err)
	require.Equal(t, SecurityLakeDefaultRotationSeconds, w.rotationSeconds)
	require.Equal(t, SecurityLakeDefaultMaxBatchBytes, w.maxBatchBytes)
	require.Equal(t, SecurityLakeDefaultMaxPendingRows, w.maxPendingRows)
}

// ---------------------------------------------------------------------------
// End-to-end with mock S3
// ---------------------------------------------------------------------------

func TestSecurityLakeWriterFlushesOnClose(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		S3Client:        mock,
		AccountID:       "111111111111",
		CallerARN:       "arn:aws:iam::111111111111:role/test",
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	for i := 0; i < 3; i++ {
		w.Write(context.Background(), sampleDecisionEvent())
	}
	require.Empty(t, mock.Puts(), "no rotation should have fired yet")

	w.Close()

	puts := mock.Puts()
	require.Equal(t, 1, len(puts))
	require.Equal(t, "test-bucket", puts[0].Bucket)
	require.Contains(t, puts[0].Key, "region=us-east-1/eventday=")
	require.Contains(t, puts[0].Key, "/eventhour=")
	require.Contains(t, puts[0].Key, "/api_activity-")
	require.Contains(t, puts[0].Key, ".parquet")
	require.NotEmpty(t, puts[0].Body)

	st := w.Status()
	require.True(t, st.WritesOK)
	require.Equal(t, int64(3), st.TotalEvents)
	require.Equal(t, int64(1), st.TotalFilesWritten)
	require.Greater(t, st.TotalBytesWritten, int64(0))
}

func TestSecurityLakeWriterPartitionsByClassUID(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		S3Client:        mock,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	// One class-6003 decision + one synthetic with class 7777.
	w.Write(context.Background(), sampleDecisionEvent())
	syn := sampleDecisionEvent()
	syn.ClassUID = 7777
	syn.ClassName = "Synthetic"
	w.Write(context.Background(), syn)
	w.Close()

	puts := mock.Puts()
	require.Equal(t, 2, len(puts))
	prefixes := make(map[string]bool)
	for _, p := range puts {
		if contains(p.Key, "/api_activity-") {
			prefixes["api_activity"] = true
		}
		if contains(p.Key, "/class-7777-") {
			prefixes["class-7777"] = true
		}
	}
	require.True(t, prefixes["api_activity"])
	require.True(t, prefixes["class-7777"])
}

func TestSecurityLakeWriterFlushesOnSizeCap(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		MaxBatchBytes:   2048,
		S3Client:        mock,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	for i := 0; i < 3; i++ {
		w.Write(context.Background(), sampleDecisionEvent())
	}
	w.Close()
	require.Equal(t, 2, len(mock.Puts()))
}

func TestSecurityLakeWriterFlushesOnRotationTimer(t *testing.T) {
	mock := &mockS3Client{}
	now := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)
	clockMu := sync.Mutex{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 1,
		S3Client:        mock,
		Now: func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return now
		},
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))
	defer w.Close()

	w.Write(context.Background(), sampleDecisionEvent())

	clockMu.Lock()
	now = now.Add(5 * time.Second)
	clockMu.Unlock()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(mock.Puts()) >= 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("rotation timer did not fire within 5s")
}

func TestSecurityLakeWriterDroppedOnOverflow(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		MaxPendingRows:  2,
		S3Client:        mock,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	for i := 0; i < 4; i++ {
		w.Write(context.Background(), sampleDecisionEvent())
	}
	st := w.Status()
	require.Equal(t, int64(2), st.DroppedEvents)
	require.Equal(t, 2, st.PendingRows)
	w.Close()
}

func TestSecurityLakeWriterStatusForMCP(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		S3Client:        mock,
		AccountID:       "111111111111",
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))
	defer w.Close()

	st := w.Status()
	require.True(t, st.Configured)
	require.Equal(t, "test-bucket", st.Bucket)
	require.Equal(t, "us-east-1", st.Region)
	require.Equal(t, "111111111111", st.AccountID)
	require.Equal(t, 600, st.RotationSeconds)
	require.True(t, st.WritesOK)
}

func TestSecurityLakeWriterRecordsErrorOnPutObjectFailure(t *testing.T) {
	mock := &mockS3Client{putErr: errors.New("AccessDenied: simulated")}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		S3Client:        mock,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	w.Write(context.Background(), sampleDecisionEvent())
	w.Close()

	st := w.Status()
	assert.False(t, st.WritesOK)
	assert.Contains(t, st.LastError, "s3 put_object failed")
}

func TestSecurityLakeWriterDefaultsMatchSpec(t *testing.T) {
	require.Equal(t, 300, SecurityLakeDefaultRotationSeconds)
	require.Equal(t, 10*1024*1024, SecurityLakeDefaultMaxBatchBytes)
}

// JSON round-trip verifies the resources_json column carries valid JSON
// the operator can json_extract in Athena.
func TestSecurityLakeRowResourcesJSONIsValid(t *testing.T) {
	row := securityLakeRowFromEvent(sampleDecisionEvent())
	var resources []Resource
	require.NoError(t, json.Unmarshal([]byte(row.ResourcesJSON), &resources))
	require.Equal(t, 1, len(resources))
	require.Equal(t, "public.users", resources[0].Name)

	var ext map[string]any
	require.NoError(t, json.Unmarshal([]byte(row.UnmappedIAMJITExtJSON), &ext))
	require.Equal(t, "postgresql", ext["dialect"])
}

// TestExporterWiresSecurityLake confirms the Exporter fan-out includes
// the Security Lake writer when one is set (additive integration).
func TestExporterWiresSecurityLake(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		S3Client:        mock,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	exp := NewExporter(nil, nil, "127.0.0.1:5433", "")
	exp.SecurityLake = w
	require.True(t, exp.Enabled(), "Exporter must report Enabled when SecurityLake is wired")

	require.NoError(t, exp.Emit(context.Background(), sampleDecisionEvent()))
	require.NoError(t, exp.Shutdown(context.Background()))

	// Close() inside Shutdown flushes the pending batch.
	require.Equal(t, 1, len(mock.Puts()),
		"Exporter.Emit must reach the Security Lake writer")

	// ExporterStatus surface the security_lake block.
	exp2 := NewExporter(nil, nil, "127.0.0.1:5433", "")
	w2, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket-2", Region: "us-west-2",
		RotationSeconds: 600, S3Client: mock,
	})
	require.NoError(t, err)
	require.NoError(t, w2.Start(context.Background()))
	defer w2.Close()
	exp2.SecurityLake = w2
	st := exp2.Status()
	require.NotNil(t, st.SecurityLake)
	require.Equal(t, "test-bucket-2", st.SecurityLake.Bucket)
}

// Helper: substring check.
func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}
