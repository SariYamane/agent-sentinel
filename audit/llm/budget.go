package llm

import (
	"agent-sentinel/runguard"
	"errors"
	"github.com/openai/openai-go/option"
	"github.com/rs/zerolog/log"
	"net/http"
	"sync/atomic"
	"time"
)

var ErrRequestBudgetExceeded = errors.New("llm: audit request budget exceeded")

var (
	requestLimit  atomic.Int64
	requestUsed   atomic.Int64
	requestDenied atomic.Int64
)

// SetRequestLimit sets the max number of HTTP attempts for this process, which
// serves one task. n<=0 means unlimited. Call it before any client is used.
func SetRequestLimit(n int) {
	if n < 0 {
		n = 0
	}
	requestLimit.Store(int64(n))
	requestUsed.Store(0)
	requestDenied.Store(0)
}

func BudgetSnapshot() (limit, used, rejected int64) {
	return requestLimit.Load(), requestUsed.Load(), requestDenied.Load()
}

// reserveAttempt takes one attempt from the budget and returns its number.
// The compare-and-swap keeps used<=limit for any number of goroutines.
func reserveAttempt(limit int64) (int64, bool) {
	for {
		cur := requestUsed.Load()
		if limit > 0 && cur >= limit {
			return cur, false
		}
		if requestUsed.CompareAndSwap(cur, cur+1) {
			return cur + 1, true
		}
	}
}

// BudgetMiddleware runs once per HTTP attempt, including the SDK's retries, so
// a reserved attempt is what reaches next and nothing else does.
func BudgetMiddleware(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
	// no traffic would happen, and the SDK returns this same error right after
	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	retry := req.Header.Get("X-Stainless-Retry-Count")
	limit := requestLimit.Load()

	n, ok := reserveAttempt(limit)
	if ok {
		log.Info().Msgf("audit_budget: attempt %d/%d retry=%s", n, limit, retry)
		return next(req)
	}

	rejected := requestDenied.Add(1)
	log.Warn().Msgf("audit_budget: rejected limit=%d used=%d rejected=%d retry=%s", limit, n, rejected, retry)

	// Every rejection trips, though only the first has any effect: a caller
	// that sees this error can then rely on runguard.Aborted being true.
	runguard.Trip("audit_request_budget_exceeded", map[string]any{
		"limit":       limit,
		"used":        n,
		"rejected":    rejected,
		"retry_count": retry,
		"time":        time.Now().Format(time.RFC3339Nano),
	})

	// The SDK treats a nil response as a connection error and retries it; this
	// header makes it return the error straight away (see shouldRetry).
	header := http.Header{}
	header.Set("X-Should-Retry", "false")
	return &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     header,
		Body:       http.NoBody,
		Request:    req,
	}, ErrRequestBudgetExceeded
}
