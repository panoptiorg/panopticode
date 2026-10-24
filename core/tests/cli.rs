// End-to-end checks of the `taint` command line on the bundled CGF.
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `taint` over the three repositories of the README quickstart, from a
/// directory that is not the repository root.
fn taint(args: &[&str]) -> Output {
    let cgf = root().join("testdata/cgf");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_panopticode"));
    cmd.arg("taint").current_dir(std::env::temp_dir());
    for r in ["webapp", "federation", "backend"] {
        cmd.arg("--cgf").arg(cgf.join(r));
    }
    cmd.args(args).output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

fn chains() -> Vec<Value> {
    let o = taint(&[]);
    assert_eq!(o.status.code(), Some(0));
    serde_json::from_str(&stdout(&o)).unwrap()
}

#[test]
fn built_in_catalog_is_the_example_catalog() {
    let a = taint(&[]);
    assert!(stderr(&a).contains("catalog: built-in example (pass --catalog <file> to use your own)"));
    let file = root().join("catalog.example.toml");
    let b = taint(&["--catalog", file.to_str().unwrap()]);
    assert!(!stderr(&b).contains("built-in"));
    assert_eq!(stdout(&a), stdout(&b));
    // the inert rules are counted on one line, and listed with --verbose
    assert_eq!(stderr(&a).matches("catalog-warn: inert rule").count(), 0);
    assert!(stderr(&a).contains("inert rules match no call site (list them with --verbose)"));
    let v = taint(&["--verbose"]);
    assert!(stderr(&v).matches("catalog-warn: inert rule").count() > 1);
}

#[test]
fn an_empty_cgf_dir_is_an_error() {
    let dir = std::env::temp_dir().join(format!("pc-empty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_panopticode"))
        .args(["graph-dump", "--cgf"])
        .arg(&dir)
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("Error: no CGF files (*.pb) in "), "{}", stderr(&o));
}

#[test]
fn fail_on_exit_codes() {
    let cs = chains();
    let has = |class: &str| cs.iter().any(|c| c["sink_class"] == class);
    assert!(has("sqli") && !has("exec"), "fixture assumption");
    for (spec, code) in [("sqli", 3), ("exec,sqli", 3), ("any", 3), ("exec", 0), ("sqlii", 2), ("exec,nope", 2)] {
        let o = taint(&["--fail-on", spec]);
        assert_eq!(o.status.code(), Some(code), "--fail-on {spec}: {}", stderr(&o));
        // the output is written before the verdict
        if code != 2 {
            assert_eq!(serde_json::from_str::<Vec<Value>>(&stdout(&o)).unwrap().len(), cs.len());
        }
    }
    let o = taint(&["--fail-on", "sqlii"]);
    assert!(stderr(&o).contains("\"sqlii\" is not a sink class"), "{}", stderr(&o));
    assert!(stdout(&o).is_empty(), "a usage error runs nothing");
}

#[test]
fn sarif_has_one_result_per_chain() {
    let cs = chains();
    let o = taint(&["--format", "sarif"]);
    assert_eq!(o.status.code(), Some(0));
    let v: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["$schema"], "https://json.schemastore.org/sarif-2.1.0.json");
    let run = &v["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "panopticode");
    assert_eq!(run["tool"]["driver"]["version"], env!("CARGO_PKG_VERSION"));
    let mut classes: Vec<_> = cs.iter().map(|c| c["sink_class"].as_str().unwrap()).collect();
    classes.sort();
    classes.dedup();
    let rules: Vec<_> = run["tool"]["driver"]["rules"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(rules, classes);
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), cs.len());
    for (r, c) in results.iter().zip(&cs) {
        assert_eq!(r["ruleId"], c["sink_class"]);
        assert_eq!(r["level"], "warning");
        let flow = r["codeFlows"][0]["threadFlows"][0]["locations"].as_array().unwrap();
        assert_eq!(flow.len(), c["route"]["hops"].as_array().unwrap().len());
        assert_eq!(r["partialFingerprints"]["panopticodeRoute/v1"], c["route"]["fingerprint"]);
        assert_eq!(r["properties"]["routeId"], c["route"]["id"]);
        assert_eq!(r["locations"].as_array().unwrap().len(), 1);
    }
    // the webapp's spans are relative, so its locations hang off a base id
    assert!(run["originalUriBaseIds"]["webapp"]["description"]["text"].is_string());
}

#[test]
fn text_has_a_block_per_chain_and_a_summary() {
    let n = chains().len();
    let o = taint(&["--format", "text"]);
    assert_eq!(o.status.code(), Some(0));
    let t = stdout(&o);
    assert_eq!(t.matches("\n  route ").count() + usize::from(t.starts_with("  route ")), n);
    assert!(t.trim_end().lines().last().unwrap().starts_with(&format!("{n} findings: ")), "{t}");
    assert!(t.contains(" → "));
}

#[test]
fn locations_carry_columns_and_the_source_hop_a_span() {
    let cs = chains();
    for c in &cs {
        let hops = c["route"]["hops"].as_array().unwrap();
        assert_eq!(hops[0]["kind"], "source");
        assert!(hops[0]["file"].is_string() && hops[0]["line"].is_number(), "{}", hops[0]);
        assert_eq!(c["route"]["fingerprint"].as_str().unwrap().len(), 12);
        assert_ne!(c["route"]["fingerprint"], c["route"]["id"]);
    }
    assert!(cs.iter().any(|c| c["sink_span"]["col"].is_number()));
}

/// A fake frontend that records its argv, copies a real CGF over --out, and
/// writes the manifest `impact` reads. Proves `--fe-arg` values reach the
/// frontend after the built-in arguments, in order.
#[test]
fn impact_passes_fe_args_to_the_frontend_in_order() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = std::env::temp_dir().join(format!("pc-fe-arg-{}", std::process::id()));
    let out = tmp.join("cgf-out");
    let store = tmp.join("store");
    std::fs::create_dir_all(&out).unwrap();

    let fixture = root().join("testdata/cgf/webapp");
    let script = format!(
        r#"#!/bin/sh
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--out" ]; then out="$a"; fi
  prev="$a"
done
printf '%s\n' "$@" > "$out/argv.txt"
cp -R "{}/." "$out/"
printf '{{"base":"aaaaaaaa","head":"bbbbbbbb","changed_files":[],"changed_fns":[]}}' > "$out/manifest.json"
"#,
        fixture.display()
    );
    let fe = tmp.join("fake-fe.sh");
    std::fs::write(&fe, script).unwrap();
    std::fs::set_permissions(&fe, std::fs::Permissions::from_mode(0o755)).unwrap();

    let repo = tmp.join("repo");
    let o = Command::new(env!("CARGO_BIN_EXE_panopticode"))
        .args([
            "impact",
            "--repo",
            repo.to_str().unwrap(),
            "--base",
            "aaaaaaaa",
            "--head",
            "bbbbbbbb",
            "--store",
            store.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--scope",
            "src/",
            "--fe",
            fe.to_str().unwrap(),
            "--fe-arg",
            "--repo-id",
            "--fe-arg",
            "example.com/webapp",
            "--fe-arg=--adapter",
            "--fe-arg=gateway",
        ])
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));

    let argv: Vec<String> = std::fs::read_to_string(out.join("argv.txt"))
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    let expected = vec![
        "build".to_string(),
        repo.to_string_lossy().to_string(),
        "--out".to_string(),
        out.to_string_lossy().to_string(),
        "--mode".to_string(),
        "mr".to_string(),
        "--base".to_string(),
        "aaaaaaaa".to_string(),
        "--head".to_string(),
        "bbbbbbbb".to_string(),
        "--scope".to_string(),
        "src/".to_string(),
        "--repo-id".to_string(),
        "example.com/webapp".to_string(),
        "--adapter".to_string(),
        "gateway".to_string(),
    ];
    assert_eq!(argv, expected, "frontend argv order wrong");

    std::fs::remove_dir_all(&tmp).ok();
}
