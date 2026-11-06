// Per-phase wall time + RSS, one JSON line per phase on stderr (prefix-free):
// {"phase":"summaries","wall_ms":123,"rss_peak_bytes":...,"rss_now_bytes":...,<counts>}.
// Overhead is two clock reads and one /proc/getrusage read per phase — never
// per function — so a run's chains and timings are unaffected. `counts` carry
// the numbers that explain the phase's memory (functions, nodes, summaries…).

use serde_json::{Map, Value};
use std::time::Instant;

/// End a phase: emit its JSON line. `counts` are appended after the standard
/// fields; a `None` RSS field is omitted (unsupported platform, or /proc gone).
pub fn end(name: &str, t0: Instant, counts: &[(&str, Value)]) {
    let mut obj = Map::new();
    obj.insert("phase".into(), Value::String(name.to_string()));
    obj.insert("wall_ms".into(), Value::from(t0.elapsed().as_millis() as u64));
    let (peak, now) = rss();
    if let Some(p) = peak {
        obj.insert("rss_peak_bytes".into(), Value::from(p));
    }
    if let Some(n) = now {
        obj.insert("rss_now_bytes".into(), Value::from(n));
    }
    for (k, v) in counts {
        obj.insert((*k).to_string(), v.clone());
    }
    eprintln!("{}", Value::Object(obj));
}

/// (peak RSS so far, current RSS) in bytes.
/// Linux: VmHWM / VmRSS from /proc/self/status. Elsewhere: getrusage
/// `ru_maxrss` (bytes on macOS, KiB on the BSDs); there is no portable
/// current-RSS read, so `rss_now_bytes` is simply absent there.
#[cfg(target_os = "linux")]
fn rss() -> (Option<u64>, Option<u64>) {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return (None, None);
    };
    let (mut peak, mut now) = (None, None);
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("VmHWM:") {
            peak = parse_status_kb(v);
        } else if let Some(v) = line.strip_prefix("VmRSS:") {
            now = parse_status_kb(v);
        }
    }
    (peak, now)
}

#[cfg(target_os = "linux")]
fn parse_status_kb(v: &str) -> Option<u64> {
    let kb: u64 = v.trim().split_whitespace().next()?.parse().ok()?;
    Some(kb.saturating_mul(1024))
}

#[cfg(not(target_os = "linux"))]
fn rss() -> (Option<u64>, Option<u64>) {
    // Peak only: ru_maxrss is bytes on macOS, KiB on the other BSDs.
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut ru) != 0 {
            return (None, None);
        }
        let scale: u64 = if cfg!(target_os = "macos") { 1 } else { 1024 };
        (Some((ru.ru_maxrss as u64).saturating_mul(scale)), None)
    }
}

/// Return free allocator pages to the OS. ru_maxrss never falls, so a phase
/// whose freed pages linger sets the peak for every later phase; relieving
/// after a burst keeps the peak near the live set. A no-op where there is no
/// portable relief call (musl's allocator returns large free regions itself,
/// as does Linux when the arena allocator is disabled).
#[cfg(target_os = "macos")]
pub fn pressure_relief() {
    extern "C" {
        fn malloc_zone_pressure_relief(zone: *mut libc::malloc_zone_t, num_pages: usize);
    }
    unsafe {
        malloc_zone_pressure_relief(libc::malloc_default_zone(), 0);
        // Small allocations live in the nano zone, which the default zone's
        // relief pass does not reach; reach it through a probe pointer.
        let probe = libc::malloc(8);
        if !probe.is_null() {
            let zone = libc::malloc_zone_from_ptr(probe);
            malloc_zone_pressure_relief(zone, 0);
            libc::free(probe);
        }
    }
}

/// glibc's arena allocator keeps freed heaps in per-thread arenas and returns
/// them to the OS only at exit; malloc_trim(0) walks every arena and madvise(2)s
/// the free pages away. Production runs glibc (debian bookworm), where a burst
/// phase's freed pages would otherwise set VmHWM for every later phase.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn pressure_relief() {
    unsafe {
        libc::malloc_trim(0);
    }
}

#[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
pub fn pressure_relief() {}
