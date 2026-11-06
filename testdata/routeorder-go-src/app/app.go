// Package app — route-order sensitivity fixture.
//
// HandleJoin fans ONE source fact through a callee whose summary carries three
// flow rows (one per request field) into three pass-through calls that rejoin
// at one sink argument. All three rows are compatible with the whole-object
// fact at the Join call site, so the order the rows are APPLIED in sets the
// taint order of the three result ports; the worklist is LIFO, so the
// LAST-applied row's leg is explored first and wins the sink argument's pred.
// A sorted application always applies the Note row last (Wrap#3 leg wins);
// an application order that sorts by hash (per-process SipHash seed) applies
// the Mask row last in some seeds — the Wrap#2 leg wins instead — so the
// route's hop list and route id differ from process to process while the
// chain itself is identical. This is the fixture that makes the defect
// observable: determinism.sh runs the binary in separate processes, so
// unsorted code flips the route id here, and sorted code never does.
//
// Shape (per leg): req (source, whole object) → Join's per-field summary rows
// → three result ports → three Wrap call sites → one variadic sink argument
// (log.Fatal). The frontend's port-0 tuple alias (result port 0 also feeds the
// other legs' arguments) does not stabilize this shape: the port-0 leg is
// never the last-applied row under a sorted application, and under a hashed
// order the winner is whatever row lands last.
package app

import (
	"context"
	"log"

	"example.com/routeorder/pb"
)

type Implementation struct {
	pb.UnimplementedOrderServer
}

func New() *Implementation { return &Implementation{} }

// Join returns all three request fields. Its summary carries one row per
// field out of Param(0) (path [i][Field] → Return i), all compatible with a
// whole-object fact at the call site — the application order of those rows is
// what decides which Wrap site the local backtrace passes through.
func Join(r *pb.OrderRequest) (string, string, string) {
	return r.Query, r.Mask, r.Note
}

// Wrap is a pass-through frame: its call site labels the leg the backtrace
// took. Three distinct call sites (different lines) make the legs
// distinguishable in the route's hop list.
func Wrap(s string) string { return s + "." }

// HandleJoin is the trigger handler. See the package comment.
func (i *Implementation) HandleJoin(ctx context.Context, req *pb.OrderRequest) error {
	u, p, n := Join(req)
	a := Wrap(u)
	b := Wrap(p)
	c := Wrap(n)
	log.Fatal(a, b, c) // log-class sink; the winning leg must not depend on hash seeds
	return nil
}
