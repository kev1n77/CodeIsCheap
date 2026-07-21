use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

use codeischeap_storage::CaptureMetrics;
use serde::{Deserialize, Serialize};

const BETA_METRICS_VERSION: &str = "0.1";
const BETA_METRICS_SLOT_A: &str = "beta-metrics.a.v0.1.json";
const BETA_METRICS_SLOT_B: &str = "beta-metrics.b.v0.1.json";
const MAX_BETA_METRICS_BYTES: u64 = 16 * 1024;

#[derive(Debug)]
pub enum BetaMetricsError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Invalid(&'static str),
}

impl fmt::Display for BetaMetricsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "beta metrics I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "beta metrics JSON is invalid: {error}"),
            Self::Invalid(detail) => write!(formatter, "beta metrics are invalid: {detail}"),
        }
    }
}

impl std::error::Error for BetaMetricsError {}

impl From<std::io::Error> for BetaMetricsError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for BetaMetricsError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BetaSessionMetrics {
    pub first_capture_elapsed_ms: Option<u64>,
    pub completed_session_count: u64,
    pub unclean_session_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BetaMetricsRecord {
    schema_version: String,
    generation: u64,
    first_launch_at_unix_ms: u64,
    first_capture_elapsed_ms: Option<u64>,
    first_capture_eligible: bool,
    completed_session_count: u64,
    unclean_session_count: u64,
    active_session_started_at_unix_ms: Option<u64>,
}

pub struct BetaMetricsTracker {
    directory: PathBuf,
    record: Option<BetaMetricsRecord>,
    session_started: bool,
}

impl BetaMetricsTracker {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            record: None,
            session_started: false,
        }
    }

    pub fn begin_session(
        &mut self,
        now_unix_ms: u64,
        capture_metrics: CaptureMetrics,
        first_capture_eligible: bool,
    ) -> Result<(), BetaMetricsError> {
        if self.session_started {
            return Ok(());
        }
        if now_unix_ms == 0 {
            return Err(BetaMetricsError::Invalid("session time must be positive"));
        }
        let mut record = self.load_latest()?.unwrap_or(BetaMetricsRecord {
            schema_version: BETA_METRICS_VERSION.to_owned(),
            generation: 0,
            first_launch_at_unix_ms: now_unix_ms,
            first_capture_elapsed_ms: None,
            first_capture_eligible: first_capture_eligible
                && capture_metrics.earliest_capture_at_unix_ms.is_none(),
            completed_session_count: 0,
            unclean_session_count: 0,
            active_session_started_at_unix_ms: None,
        });
        if record.active_session_started_at_unix_ms.is_some() {
            record.completed_session_count = record
                .completed_session_count
                .checked_add(1)
                .ok_or(BetaMetricsError::Invalid("session count overflow"))?;
            record.unclean_session_count = record
                .unclean_session_count
                .checked_add(1)
                .ok_or(BetaMetricsError::Invalid("unclean session count overflow"))?;
        }
        observe_first_capture(&mut record, capture_metrics.earliest_capture_at_unix_ms);
        record.active_session_started_at_unix_ms = Some(now_unix_ms);
        self.persist(record)?;
        self.session_started = true;
        Ok(())
    }

    pub fn observe_capture(
        &mut self,
        capture_metrics: CaptureMetrics,
    ) -> Result<(), BetaMetricsError> {
        if !self.session_started {
            return Err(BetaMetricsError::Invalid(
                "beta metrics session has not initialized",
            ));
        }
        let Some(mut record) = self.record.clone() else {
            return Err(BetaMetricsError::Invalid(
                "active session record is missing",
            ));
        };
        let previous = record.first_capture_elapsed_ms;
        let eligible = record.first_capture_eligible;
        observe_first_capture(&mut record, capture_metrics.earliest_capture_at_unix_ms);
        if record.first_capture_elapsed_ms != previous || record.first_capture_eligible != eligible
        {
            self.persist(record)?;
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Result<BetaSessionMetrics, BetaMetricsError> {
        let record = self.record.as_ref().ok_or(BetaMetricsError::Invalid(
            "beta metrics have not initialized",
        ))?;
        Ok(BetaSessionMetrics {
            first_capture_elapsed_ms: record.first_capture_elapsed_ms,
            completed_session_count: record.completed_session_count,
            unclean_session_count: record.unclean_session_count,
        })
    }

    pub fn complete_session(&mut self) -> Result<(), BetaMetricsError> {
        if !self.session_started {
            return Ok(());
        }
        let Some(mut record) = self.record.clone() else {
            return Err(BetaMetricsError::Invalid(
                "active session record is missing",
            ));
        };
        if record.active_session_started_at_unix_ms.take().is_some() {
            record.completed_session_count = record
                .completed_session_count
                .checked_add(1)
                .ok_or(BetaMetricsError::Invalid("session count overflow"))?;
            self.persist(record)?;
        }
        self.session_started = false;
        Ok(())
    }

    fn load_latest(&self) -> Result<Option<BetaMetricsRecord>, BetaMetricsError> {
        let mut records = Vec::new();
        let mut invalid_slots = 0;
        for name in [BETA_METRICS_SLOT_A, BETA_METRICS_SLOT_B] {
            let path = self.directory.join(name);
            match load_record(&path) {
                Ok(Some(record)) => records.push(record),
                Ok(None) => {}
                Err(_) => invalid_slots += 1,
            }
        }
        if records.is_empty() && invalid_slots > 0 {
            return Err(BetaMetricsError::Invalid(
                "no valid beta metrics slot remains",
            ));
        }
        records.sort_by_key(|record| record.generation);
        if records.len() == 2 && records[0].generation == records[1].generation {
            return Err(BetaMetricsError::Invalid(
                "beta metrics slots have ambiguous generations",
            ));
        }
        Ok(records.pop())
    }

    fn persist(&mut self, mut record: BetaMetricsRecord) -> Result<(), BetaMetricsError> {
        validate_record(&record, true)?;
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(BetaMetricsError::Invalid("generation overflow"))?;
        fs::create_dir_all(&self.directory)?;
        #[cfg(unix)]
        fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))?;
        let name = if record.generation % 2 == 0 {
            BETA_METRICS_SLOT_A
        } else {
            BETA_METRICS_SLOT_B
        };
        let path = self.directory.join(name);
        remove_slot_for_rewrite(&path)?;
        let mut encoded = serde_json::to_vec_pretty(&record)?;
        encoded.push(b'\n');
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_BETA_METRICS_BYTES {
            return Err(BetaMetricsError::Invalid("encoded metrics exceed 16 KiB"));
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(path)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        self.record = Some(record);
        Ok(())
    }
}

impl Drop for BetaMetricsTracker {
    fn drop(&mut self) {
        let _ = self.complete_session();
    }
}

fn observe_first_capture(record: &mut BetaMetricsRecord, earliest: Option<u64>) {
    if record.first_capture_elapsed_ms.is_some() || !record.first_capture_eligible {
        return;
    }
    let Some(earliest) = earliest else {
        return;
    };
    if earliest < record.first_launch_at_unix_ms {
        record.first_capture_eligible = false;
    } else {
        record.first_capture_elapsed_ms = Some(earliest - record.first_launch_at_unix_ms);
    }
}

fn load_record(path: &Path) -> Result<Option<BetaMetricsRecord>, BetaMetricsError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_BETA_METRICS_BYTES
    {
        return Err(BetaMetricsError::Invalid(
            "metrics slot is not a bounded file",
        ));
    }
    let record: BetaMetricsRecord = serde_json::from_slice(&fs::read(path)?)?;
    validate_record(&record, false)?;
    Ok(Some(record))
}

fn validate_record(
    record: &BetaMetricsRecord,
    allow_zero_generation: bool,
) -> Result<(), BetaMetricsError> {
    if record.schema_version != BETA_METRICS_VERSION
        || (!allow_zero_generation && record.generation == 0)
        || record.first_launch_at_unix_ms == 0
        || record.unclean_session_count > record.completed_session_count
        || record.active_session_started_at_unix_ms == Some(0)
        || (record.first_capture_elapsed_ms.is_some() && !record.first_capture_eligible)
    {
        return Err(BetaMetricsError::Invalid("record invariant failed"));
    }
    Ok(())
}

fn remove_slot_for_rewrite(path: &Path) -> Result<(), BetaMetricsError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Err(BetaMetricsError::Invalid(
            "metrics slot cannot be a directory",
        )),
        Ok(_) => fs::remove_file(path).map_err(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn captures(earliest: Option<u64>) -> CaptureMetrics {
        CaptureMetrics {
            earliest_capture_at_unix_ms: earliest,
            supported_capture_count: 0,
            parsed_capture_count: 0,
        }
    }

    #[test]
    fn first_capture_and_clean_sessions_survive_restarts() {
        let directory = tempdir().expect("temporary directory");
        {
            let mut tracker = BetaMetricsTracker::new(directory.path());
            tracker
                .begin_session(100, captures(None), true)
                .expect("begin");
            tracker
                .observe_capture(captures(Some(150)))
                .expect("observe");
            assert_eq!(
                tracker
                    .snapshot()
                    .expect("snapshot")
                    .first_capture_elapsed_ms,
                Some(50)
            );
            tracker.complete_session().expect("complete");
        }
        let mut tracker = BetaMetricsTracker::new(directory.path());
        tracker
            .begin_session(200, captures(Some(150)), false)
            .expect("restart");
        let snapshot = tracker.snapshot().expect("snapshot");
        assert_eq!(snapshot.completed_session_count, 1);
        assert_eq!(snapshot.unclean_session_count, 0);
        assert_eq!(snapshot.first_capture_elapsed_ms, Some(50));
    }

    #[test]
    fn active_marker_becomes_an_unclean_completed_session() {
        let directory = tempdir().expect("temporary directory");
        let mut tracker = BetaMetricsTracker::new(directory.path());
        tracker
            .begin_session(100, captures(None), true)
            .expect("begin");
        std::mem::forget(tracker);

        let mut restarted = BetaMetricsTracker::new(directory.path());
        restarted
            .begin_session(200, captures(None), false)
            .expect("restart");
        let snapshot = restarted.snapshot().expect("snapshot");
        assert_eq!(snapshot.completed_session_count, 1);
        assert_eq!(snapshot.unclean_session_count, 1);
    }

    #[test]
    fn corrupt_newest_slot_falls_back_to_the_previous_generation() {
        let directory = tempdir().expect("temporary directory");
        let mut tracker = BetaMetricsTracker::new(directory.path());
        tracker
            .begin_session(100, captures(None), true)
            .expect("begin");
        tracker
            .observe_capture(captures(Some(150)))
            .expect("observe");
        std::mem::forget(tracker);
        fs::write(directory.path().join(BETA_METRICS_SLOT_A), b"broken")
            .expect("corrupt newest slot");

        let mut restarted = BetaMetricsTracker::new(directory.path());
        restarted
            .begin_session(200, captures(None), false)
            .expect("fallback");
        let snapshot = restarted.snapshot().expect("snapshot");
        assert_eq!(snapshot.first_capture_elapsed_ms, None);
        assert_eq!(snapshot.unclean_session_count, 1);
    }

    #[test]
    fn invalid_slots_fail_closed_without_overwriting_them() {
        let directory = tempdir().expect("temporary directory");
        fs::write(directory.path().join(BETA_METRICS_SLOT_A), b"broken")
            .expect("write invalid slot");
        let mut tracker = BetaMetricsTracker::new(directory.path());
        assert!(tracker.begin_session(100, captures(None), true).is_err());
        assert_eq!(
            fs::read(directory.path().join(BETA_METRICS_SLOT_A)).expect("slot remains"),
            b"broken"
        );
    }

    #[test]
    fn existing_empty_installations_are_not_first_capture_samples() {
        let directory = tempdir().expect("temporary directory");
        let mut tracker = BetaMetricsTracker::new(directory.path());
        tracker
            .begin_session(100, captures(None), false)
            .expect("begin existing installation");
        tracker
            .observe_capture(captures(Some(150)))
            .expect("observe capture");

        assert_eq!(
            tracker
                .snapshot()
                .expect("snapshot")
                .first_capture_elapsed_ms,
            None
        );
    }
}
