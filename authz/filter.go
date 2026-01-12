package authz

import (
	"context"
	"fmt"
	"iter"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/grafana/authlib/types"
)

// BatchCheckItem represents an item that needs batch authorization.
type BatchCheckItem struct {
	Name      string
	Folder    string
	Group     string
	Resource  string
	Verb      string
	Namespace string
}

// FilterResult contains the result of an authorization filter operation.
// Items is the iterator yielding authorized items.
// Zookie is populated after the iterator is consumed with the latest zookie from batch checks.
type FilterResult[T any] struct {
	Items  iter.Seq2[T, error]
	Zookie *types.Zookie
}

// FilterOptions configures the behavior of FilterAuthorized.
type FilterOptions struct {
	Tracer trace.Tracer
}

// FilterOption is a function that configures FilterOptions.
type FilterOption func(*FilterOptions)

// WithTracer sets the tracer for FilterAuthorized.
func WithTracer(tracer trace.Tracer) FilterOption {
	return func(o *FilterOptions) {
		o.Tracer = tracer
	}
}

// FilterAuthorized returns a FilterResult containing an iterator that yields only authorized items
// and a pointer to the Zookie that is populated after iteration completes.
// User is extracted from context. Items are batched internally for efficient authorization checks.
// Yields (item, nil) for authorized items, (zero, err) on error.
func FilterAuthorized[T any](
	ctx context.Context,
	access types.AccessClient,
	items iter.Seq[T],
	extractFn func(T) BatchCheckItem,
	opts ...FilterOption,
) FilterResult[T] {
	options := &FilterOptions{
		Tracer: noop.Tracer{},
	}
	for _, opt := range opts {
		opt(options)
	}

	var zookie types.Zookie

	iterator := func(yield func(T, error) bool) {
		ctx, span := options.Tracer.Start(ctx, "FilterAuthorized")
		defer span.End()

		user, ok := types.AuthInfoFrom(ctx)
		if !ok {
			var zero T
			span.SetAttributes(attribute.Bool("error.missing_auth", true))
			yield(zero, fmt.Errorf("%w: in context", ErrMissingAuthInfo))
			return
		}

		var totalItems, authorizedItems, batchCount int
		batch := make([]T, 0, types.MaxBatchCheckItems)

		flushBatch := func() bool {
			if len(batch) == 0 {
				return true
			}

			batchCount++
			authorized, cont := processBatch(ctx, access, user, batch, extractFn, yield, &zookie, options.Tracer)
			authorizedItems += authorized
			return cont
		}

		for item := range items {
			totalItems++
			batch = append(batch, item)
			if len(batch) >= types.MaxBatchCheckItems {
				if !flushBatch() {
					recordFilterMetrics(span, totalItems, authorizedItems, batchCount)
					return
				}
				batch = batch[:0]
			}
		}

		// Flush remaining items
		if len(batch) > 0 {
			flushBatch()
		}

		recordFilterMetrics(span, totalItems, authorizedItems, batchCount)
	}

	return FilterResult[T]{
		Items:  iterator,
		Zookie: &zookie,
	}
}

func recordFilterMetrics(span trace.Span, total, authorized, batches int) {
	span.SetAttributes(
		attribute.Int("items.total", total),
		attribute.Int("items.authorized", authorized),
		attribute.Int("batches", batches),
	)
}

// processBatch performs batch authorization and yields authorized items.
// Returns the count of authorized items and false if iteration should stop.
func processBatch[T any](
	ctx context.Context,
	access types.AccessClient,
	user types.AuthInfo,
	batch []T,
	extractFn func(T) BatchCheckItem,
	yield func(T, error) bool,
	zookie *types.Zookie,
	tracer trace.Tracer,
) (int, bool) {
	ctx, span := tracer.Start(ctx, "processBatch")
	defer span.End()

	// Build batch check request
	checks := make([]types.BatchCheckItem, len(batch))
	for i, item := range batch {
		info := extractFn(item)
		checks[i] = types.BatchCheckItem{
			CorrelationID: strconv.Itoa(i),
			Verb:          info.Verb,
			Group:         info.Group,
			Resource:      info.Resource,
			Namespace:     info.Namespace,
			Name:          info.Name,
			Folder:        info.Folder,
		}
	}

	// Perform batch authorization check
	batchResp, err := access.BatchCheck(ctx, user, types.BatchCheckRequest{
		Checks: checks,
	})
	if err != nil {
		span.RecordError(err)
		var zero T
		yield(zero, err)
		return 0, false
	}

	// Store the latest zookie
	*zookie = batchResp.Zookie

	// Yield authorized items
	authorized := 0
	for i, item := range batch {
		correlationID := fmt.Sprintf("%d", i)
		if result, ok := batchResp.Results[correlationID]; ok && result.Allowed {
			authorized++
			if !yield(item, nil) {
				return authorized, false
			}
		}
	}
	return authorized, true
}
