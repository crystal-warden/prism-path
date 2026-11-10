// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Shared by the tests that write files: a scratch directory that removes itself, so a test run leaves
//! nothing in the temporary directory whether its test passed or failed.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A scratch directory removed when it goes out of scope, a failed assertion included. It reads as the path it holds.
pub struct Scratch(PathBuf);

impl Scratch {
    /// A new empty directory `<temp>/pp_<tag>_<process>_<n>`, the number telling apart two made under one tag.
    pub fn new(tag: &str) -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("pp_{tag}_{}_{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    /// The path of `name` inside the directory, as text.
    pub fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_string()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}
