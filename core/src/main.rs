// panopticode — Rust analyst core. Loads CGF, computes bottom-up taint
// summaries (Sharir–Pnueli), composes them across repositories, persists to
// Postgres, emits JSON.
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
