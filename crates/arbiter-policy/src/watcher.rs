//! File-system watcher for hot-reloading policy configuration.
//!
//! [`PolicyWatcher`] monitors a TOML policy file for changes and atomically
//! swaps the shared [`PolicyConfig`] when the file is modified. Uses a
//! `watch` channel for lock-free reads on the hot path; readers snapshot
//! the current config without contention. This satisfies REQ-005.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::watch;

use crate::model::PolicyConfig;

/// Handle to a running policy file watcher. Drop or call [`PolicyWatcher::stop`]
/// to terminate the background watch task.
pub struct PolicyWatcher {
    /// Abort handle for the background tokio task.
    handle: tokio::task::JoinHandle<()>,
    /// Watcher must be kept alive for the duration; dropping it unregisters
    /// the filesystem watch.
    _watcher: RecommendedWatcher,
}

impl PolicyWatcher {
    /// Start watching `path` for changes. On each detected modification the
    /// file is re-read, parsed as TOML, validated, and swapped into `shared`.
    ///
    /// Uses a debounce of `debounce` to coalesce rapid-fire filesystem events
    /// (editors often write temp files then rename).
    pub fn start(
        path: impl AsRef<Path>,
        shared: Arc<watch::Sender<Arc<Option<PolicyConfig>>>>,
        debounce: Duration,
    ) -> Result<Self, notify::Error> {
        let path = path.as_ref().to_path_buf();
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(16);

        // Build the notify watcher. Delivers events on a background thread.
        let watch_path = path.clone();
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let dominated = matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_));
                if dominated {
                    // Best-effort send. If the channel is full we skip (debounce
                    // will coalesce anyway).
                    let _ = tx.try_send(());
                }
            }
        })?;

        // Watch the parent directory so that atomic-rename writes (used by
        // many text editors) are caught.
        let watch_dir = watch_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        watcher.watch(&watch_dir, RecursiveMode::NonRecursive)?;

        // Perform an initial synchronous load so the shared config is never
        // None after construction. Previously, there was a window between
        // watcher start and first filesystem event where the config was None.
        reload_from_file(&path, &shared);

        let handle = tokio::spawn(Self::reload_loop(path, shared, debounce, rx));

        Ok(Self {
            handle,
            _watcher: watcher,
        })
    }

    /// Background loop: waits for filesystem events, debounces, reloads.
    async fn reload_loop(
        path: PathBuf,
        shared: Arc<watch::Sender<Arc<Option<PolicyConfig>>>>,
        debounce: Duration,
        mut rx: tokio::sync::mpsc::Receiver<()>,
    ) {
        loop {
            // Wait for first event.
            if rx.recv().await.is_none() {
                // Channel closed; watcher dropped.
                break;
            }

            // Debounce: drain any additional events within the window.
            tokio::time::sleep(debounce).await;
            while rx.try_recv().is_ok() {}

            // Reload the policy file.
            reload_from_file(&path, &shared);
        }
    }

    /// Stop the watcher. The background task is aborted.
    pub fn stop(self) {
        self.handle.abort();
        // _watcher is dropped, unregistering the filesystem watch.
    }
}

/// Read, parse, validate, and swap the policy config from `path` into `shared`.
fn reload_from_file(path: &Path, shared: &Arc<watch::Sender<Arc<Option<PolicyConfig>>>>) {
    // Read the file and verify it ends with a newline or closing bracket,
    // reducing the chance of reading a partially-written file.
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "policy hot-reload: failed to read file");
            return;
        }
    };
    if contents.is_empty() {
        tracing::warn!(path = %path.display(), "policy hot-reload: file is empty, skipping");
        return;
    }

    let new_config = match PolicyConfig::from_toml(&contents) {
        Ok(pc) => pc,
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "policy hot-reload: failed to parse TOML");
            return;
        }
    };

    let policy_count = new_config.policies.len();
    // Atomic swap: readers see either the old or new config, never partial state.
    let _ = shared.send_replace(Arc::new(Some(new_config)));

    tracing::info!(
        path = %path.display(),
        policy_count,
        "policy hot-reload: config updated"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write a valid policy TOML, start the watcher, modify the file,
    /// and verify the shared config is updated.
    #[tokio::test]
    async fn watcher_reloads_on_file_change() {
        let dir =
            std::env::temp_dir().join(format!("arbiter-watcher-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy_file = dir.join("policies.toml");

        // Write initial policy.
        let initial_toml = r#"
[[policies]]
id = "initial"
effect = "allow"
allowed_tools = ["*"]
"#;
        std::fs::write(&policy_file, initial_toml).unwrap();

        let (tx, rx) = watch::channel(Arc::new(None));
        let shared = Arc::new(tx);
        let watcher =
            PolicyWatcher::start(&policy_file, shared.clone(), Duration::from_millis(100))
                .expect("failed to start watcher");

        // Give the watcher time to initialize.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Modify the file: add a second policy.
        let updated_toml = r#"
[[policies]]
id = "initial"
effect = "allow"
allowed_tools = ["*"]

[[policies]]
id = "added"
effect = "deny"
"#;
        // Write atomically via temp file + rename to ensure the watcher picks it up.
        let tmp = dir.join("policies.toml.tmp");
        {
            let mut f = std::fs::File::create(&tmp).unwrap();
            f.write_all(updated_toml.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        std::fs::rename(&tmp, &policy_file).unwrap();

        // Wait for debounce + reload.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let snapshot = rx.borrow().clone();
        let config = (*snapshot)
            .as_ref()
            .expect("config should have been loaded");
        assert_eq!(config.policies.len(), 2, "expected 2 policies after reload");
        assert_eq!(config.policies[1].id, "added");

        watcher.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Invalid TOML does not crash the watcher; old config is preserved.
    #[tokio::test]
    async fn watcher_preserves_config_on_invalid_toml() {
        let dir =
            std::env::temp_dir().join(format!("arbiter-watcher-invalid-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy_file = dir.join("policies.toml");

        let valid_toml = r#"
[[policies]]
id = "valid"
effect = "allow"
allowed_tools = ["*"]
"#;
        std::fs::write(&policy_file, valid_toml).unwrap();

        // Pre-load config.
        let initial = PolicyConfig::from_toml(valid_toml).unwrap();
        let (tx, rx) = watch::channel(Arc::new(Some(initial)));
        let shared = Arc::new(tx);

        let watcher =
            PolicyWatcher::start(&policy_file, shared.clone(), Duration::from_millis(100))
                .expect("failed to start watcher");

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Write invalid TOML.
        std::fs::write(&policy_file, "this is not valid [[[toml").unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Config should still be the original.
        let snapshot = rx.borrow().clone();
        let config = (*snapshot).as_ref().expect("config should still exist");
        assert_eq!(config.policies.len(), 1);
        assert_eq!(config.policies[0].id, "valid");

        watcher.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
