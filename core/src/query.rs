// `panopticode query` — pure Postgres graph reads (doc 08 consumer surface):
// no extraction, no taint, just the persisted graph from a prior analyze run.
// JSON to stdout (a service invokes this as a process), stats to stderr.
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct FnRefJ {
    fqn: String,
    repo: String,
    span_file: Option<String>,
    span_line: Option<i32>,
}

/// persist writes '' span_file for contract/spanless nodes — surface as null.
fn norm_span(f: Option<String>, l: Option<i32>) -> (Option<String>, Option<i32>) {
    match f {
        Some(s) if !s.is_empty() => (Some(s), l),
        _ => (None, None),
    }
}

#[derive(Serialize)]
struct BlastOut {
    repo: String,
    graph_commit_sha: String,
    repos: Vec<String>,
    endpoints: Vec<String>,
}

pub fn blast(pg: &str, repo: &str, files: &[String]) -> Result<()> {
    let b = crate::storage::pg_blast(pg, repo, files)?;
    // '' commit_sha = foreign-contract stub row (resolve_foreign_contracts),
    // not an analyzed repo — same "not in PG" verdict the old blast.sh gave.
    let sha = match b.graph_commit_sha {
        Some(s) if !s.is_empty() => s,
        _ => anyhow::bail!("repo '{repo}' not in PG — run scripts/analyze.sh first"),
    };
    let out = BlastOut {
        repo: repo.into(),
        graph_commit_sha: sha,
        repos: b.repos,
        endpoints: b.endpoints,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    eprintln!("repos={} endpoints={}", out.repos.len(), out.endpoints.len());
    Ok(())
}

#[derive(Serialize)]
struct ReachOut {
    query: String,
    repo_filter: Option<String>,
    matches: Vec<FnRefJ>,
    repos: Vec<String>,
    endpoints: Vec<String>,
}

pub fn reach(pg: &str, fn_substr: &str, repo: Option<&str>) -> Result<()> {
    let r = crate::storage::pg_reach(pg, fn_substr, repo)?;
    if r.matches.is_empty() {
        anyhow::bail!(
            "--fn '{fn_substr}' matched no functions{}",
            repo.map(|r| format!(" in repo {r}")).unwrap_or_default()
        );
    }
    let out = ReachOut {
        query: fn_substr.into(),
        repo_filter: repo.map(Into::into),
        matches: r
            .matches
            .into_iter()
            .map(|f| {
                let (span_file, span_line) = norm_span(f.span_file, f.span_line);
                FnRefJ {
                    fqn: f.fqn,
                    repo: f.repo,
                    span_file,
                    span_line,
                }
            })
            .collect(),
        repos: r.repos,
        endpoints: r.endpoints,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    eprintln!(
        "matches={} repos={} endpoints={}",
        out.matches.len(),
        out.repos.len(),
        out.endpoints.len()
    );
    Ok(())
}

#[derive(Serialize)]
struct HopJ {
    fqn: String,
    repo: String,
    kind: &'static str,
    span_file: Option<String>,
    span_line: Option<i32>,
}

#[derive(Serialize)]
struct PathJ {
    hops: Vec<HopJ>,
}

#[derive(Serialize)]
struct PathsOut {
    from: String,
    to: String,
    paths: Vec<PathJ>,
}

pub fn path(pg: &str, from: &str, to: &str, limit: i64, max_depth: i32) -> Result<()> {
    let paths = crate::storage::pg_paths(pg, from, to, limit, max_depth)?;
    let out = PathsOut {
        from: from.into(),
        to: to.into(),
        paths: paths
            .into_iter()
            .map(|p| PathJ {
                hops: p
                    .into_iter()
                    .map(|h| {
                        let (span_file, span_line) = norm_span(h.span_file, h.span_line);
                        HopJ {
                            fqn: h.fqn,
                            repo: h.repo,
                            kind: if h.kind == 2 { "contract" } else { "fn" },
                            span_file,
                            span_line,
                        }
                    })
                    .collect(),
            })
            .collect(),
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    eprintln!(
        "paths={} limit={} max_depth={}",
        out.paths.len(),
        limit,
        max_depth
    );
    Ok(())
}
