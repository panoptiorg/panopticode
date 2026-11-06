package store

type Storage struct{}

// Selectx models a pgx-wrapper SQL exec sink: `query` is the tainted-carrying arg.
func (s *Storage) Selectx(query string) (string, error) {
	return "row:" + query, nil
}

// findBy takes a variadic arg (mirrors squirrel Where(pred, args...)).
func (s *Storage) findBy(pred string, args ...string) (string, error) {
	q := pred + args[0]
	return s.Selectx(q) // SINK
}

// FindRecordEntry flows `entry` through a VARIADIC call into the SQL sink.
func (s *Storage) FindRecordEntry(entry string) (string, error) {
	return s.findBy("entry = ?", entry)
}
