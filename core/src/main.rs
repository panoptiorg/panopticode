// panopticode — Rust analyst core. Loads CGF, runs IFDS taint tabulation,
// composes summaries (incl. cross-repo), persists to Postgres, emits JSON.
mod proto;
mod trace;
mod ids;
mod catalog;
mod graph;
mod normalize;
mod ifds;
mod summarystore;
mod compose;
mod heap;
mod impact;
mod report;
mod witness;
mod backward;
mod storage;
mod query;
mod cli;

fn main() -> anyhow::Result<()> {
    cli::run()
}
