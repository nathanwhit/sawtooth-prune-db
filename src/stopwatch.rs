#![allow(dead_code)]

use dashmap::DashMap;
use fxhash::FxBuildHasher;
use once_cell::sync::Lazy;
use std::time::{Duration, Instant};

pub static METRICS: Lazy<DashMap<String, Metric, FxBuildHasher>> = Lazy::new(DashMap::default);

#[derive(Clone, PartialEq)]
pub struct Metric {
    duration: Duration,
    count: u64,
}

impl Default for Metric {
    fn default() -> Self {
        Self {
            duration: Default::default(),
            count: 0,
        }
    }
}

impl Metric {
    pub fn add(&mut self, new: Duration) {
        self.duration += new;
        self.count += 1;
    }
}

#[derive(Clone, Debug)]
pub struct StopWatch {
    start: Instant,
    last: Instant,
}

impl StopWatch {
    pub fn start() -> Self {
        let start = Instant::now();
        Self {
            last: start.clone(),
            start,
        }
    }

    pub fn elapsed_total(&mut self) -> Duration {
        let now = Instant::now();
        let ret = now.duration_since(self.start);
        self.last = now;
        ret
    }

    pub fn elapsed(&mut self) -> Duration {
        let now = Instant::now();
        let ret = now.duration_since(self.last);
        self.last = now;
        ret
    }

    pub fn record(&mut self, event: &str) {
        let new = self.elapsed();
        METRICS.entry(event.into()).or_default().add(new);
    }

    pub fn record_total(&mut self, event: &str) {
        let new = self.elapsed_total();
        METRICS.entry(event.into()).or_default().add(new);
    }
}

pub fn timed<F, O>(event: &str, op: F) -> O
where
    F: FnOnce() -> O,
{
    let mut stopwatch = StopWatch::start();
    let ret = op();
    stopwatch.record(event);
    ret
}
