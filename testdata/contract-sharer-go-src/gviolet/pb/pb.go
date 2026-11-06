package pb

import "context"

// Vendored client types of the ledger service (the generated gRPC client the
// resolver calls across the boundary).

type RecordRequest struct{ Entry string }

type RecordResponse struct{ Ok bool }

// LedgerClient is the generated gRPC client interface (vendored copy).
type LedgerClient interface {
	Record(ctx context.Context, in *RecordRequest) (*RecordResponse, error)
}
