package app

import (
	"context"

	"example.com/gping/pb"
)

type Implementation struct {
	pb.UnimplementedPingServer
}

func New() *Implementation { return &Implementation{} }

// Send drops its argument: the handler summary has NO flows and NO sinks, so
// the contract view gquiet composes is empty while gviolet's (over the ledger
// service) carries a SQL sink. Whether the shared GraphQL contract's published
// view ends up violet's or quiet's decides whether the client operation has a
// finding at all — the run-to-run choice this fixture exists to expose.
func (i *Implementation) Send(ctx context.Context, req *pb.SendRequest) (*pb.SendResponse, error) {
	return &pb.SendResponse{Ok: req.GetEntry() == ""}, nil
}
