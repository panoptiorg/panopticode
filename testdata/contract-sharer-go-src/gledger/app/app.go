package app

import (
	"context"

	"example.com/gledger/pb"
	"example.com/gledger/store"
)

type Implementation struct {
	pb.UnimplementedLedgerServer
	storage *store.Storage
}

func New() *Implementation { return &Implementation{storage: &store.Storage{}} }

// Record: req.GetEntry() (SOURCE) -> FindRecordEntry -> Selectx (SINK). The
// GraphQL resolvers of the two contract-sharer repos call THIS method, so the
// contract view gviolet composes carries the sink while gquiet's carries none.
func (i *Implementation) Record(ctx context.Context, req *pb.RecordRequest) (*pb.RecordResponse, error) {
	row, err := i.storage.FindRecordEntry(req.GetEntry())
	if err != nil {
		return nil, err
	}
	return &pb.RecordResponse{Ok: row != ""}, nil
}
