//! Spawns the real `dank-askpass` binary and checks the caller allowlist.
//!
//! No DMS plugin is involved: the socket path is pointed at a path that does
//! not exist, so a run that clears the allowlist gate fails with the plugin's
//! "not listening" error instead. Comparing that message with the allowlist
//! refusal proves the gate runs first.
//!
//! `dank-askpass` reports nothing on stdout on refusal, so no credential can
//! leak even in test runs.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

/// Unique scratch dirs per test; cargo runs tests in threads of one process.
static DIR_SEQ: AtomicU32 = AtomicU32::new(0);

fn askpass_bin() -> &'static str {
    env!("CARGO_BIN_EXE_dank-askpass")
}

/// Our own binary — the parent the spawned `dank-askpass` will resolve.
fn own_exe() -> PathBuf {
    std::fs::read_link("/proc/self/exe").expect("own exe")
}

fn own_name() -> String {
    own_exe()
        .file_name()
        .expect("own exe has a name")
        .to_string_lossy()
        .into_owned()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dank-askpass-{}-{}-{}",
        std::process::id(),
        name,
        DIR_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn write_allowlist(dir: &Path, entries: &[&str]) -> PathBuf {
    let path = dir.join("allowlist");
    let mut text = String::new();
    for entry in entries {
        text.push_str(entry);
        text.push('\n');
    }
    std::fs::write(&path, text).expect("write allowlist");
    path
}

fn run(socket: &Path, allowlist: &Path) -> Output {
    Command::new(askpass_bin())
        .arg("PROMPT")
        .env("DANK_PINENTRY_ALLOWLIST", allowlist)
        .env("DANK_PINENTRY_SOCKET_PATH", socket)
        .env_remove("SSH_ASKPASS_PROMPT")
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("SSH_ASKPASS_REQUIRE")
        .output()
        .expect("spawn dank-askpass")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_listed_caller_clears_the_gate_and_fails_on_the_socket() {
    let scratch = scratch("allowed");
    let allowlist = write_allowlist(&scratch, &[&own_name()]);

    let out = run(&scratch.join("missing.sock"), &allowlist);
    let err = stderr(&out);

    assert!(!out.status.success());
    assert!(
        err.contains("not listening"),
        "a listed caller must reach the socket check, got: {err}"
    );
    assert!(
        !err.contains("refusing prompt"),
        "gate must allow a listed caller: {err}"
    );

    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn a_pathglob_listed_caller_clears_the_gate() {
    let scratch = scratch("pathglob");
    let entry = format!("*/{}", own_name());
    let allowlist = write_allowlist(&scratch, &[&entry]);

    let err = stderr(&run(&scratch.join("missing.sock"), &allowlist));

    assert!(
        err.contains("not listening"),
        "a path-globbed caller must reach the socket check, got: {err}"
    );
    assert!(!err.contains("refusing prompt"), "{err}");

    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn an_unlisted_caller_is_refused_before_the_socket_check() {
    let scratch = scratch("denied");
    let allowlist = write_allowlist(&scratch, &["definitely-not-our-test-binary"]);

    let out = run(&scratch.join("missing.sock"), &allowlist);
    let err = stderr(&out);

    assert!(!out.status.success());
    assert!(
        err.contains("refusing prompt"),
        "an unlisted caller must be refused, got: {err}"
    );
    assert!(
        !err.contains("not listening"),
        "refusal must precede the socket check: {err}"
    );
    assert!(
        out.stdout.is_empty(),
        "no secret may be printed for a refused caller: {:?}",
        out.stdout
    );

    std::fs::remove_dir_all(&scratch).ok();
}

#[test]
fn a_missing_allowlist_leaves_the_gate_inert() {
    let scratch = scratch("inert");
    let allowlist = scratch.join("does-not-exist");

    let err = stderr(&run(&scratch.join("missing.sock"), &allowlist));

    assert!(
        err.contains("not listening"),
        "a missing allowlist must not lock the caller out, got: {err}"
    );
    assert!(!err.contains("refusing prompt"), "{err}");

    std::fs::remove_dir_all(&scratch).ok();
}
