package pb

import "context"

type RecordRequest struct{ Entry string }

func (r *RecordRequest) GetEntry() string { return r.Entry }

type RecordResponse struct{ Ok bool }

// LedgerServer is the generated gRPC server interface.
type LedgerServer interface {
	Record(context.Context, *RecordRequest) (*RecordResponse, error)
}

// UnimplementedLedgerServer is embedded by server implementations.
type UnimplementedLedgerServer struct{}

func (UnimplementedLedgerServer) Record(context.Context, *RecordRequest) (*RecordResponse, error) {
	return nil, nil
}
