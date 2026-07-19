use crate::model::{TrafficCounters, TrafficRates};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone)]
struct Sample {
    counters: TrafficCounters,
    at: Instant,
}

/// Tracks previous counters to compute live rates.
#[derive(Debug, Default)]
pub struct RateTracker {
    local: Option<Sample>,
    devices: HashMap<String, Sample>,
}

impl RateTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_local(&mut self, counters: &TrafficCounters) -> TrafficRates {
        let now = Instant::now();
        let rates = if let Some(prev) = &self.local {
            let dt = now.duration_since(prev.at).as_secs_f64().max(0.001);
            TrafficRates {
                rx_bps: ((counters.rx_bytes.saturating_sub(prev.counters.rx_bytes)) as f64 / dt)
                    as u64,
                tx_bps: ((counters.tx_bytes.saturating_sub(prev.counters.tx_bytes)) as f64 / dt)
                    as u64,
            }
        } else {
            TrafficRates::default()
        };
        self.local = Some(Sample {
            counters: counters.clone(),
            at: now,
        });
        rates
    }

    /// key should be stable (preferably MAC).
    pub fn update_device(
        &mut self,
        key: &str,
        rx: Option<u64>,
        tx: Option<u64>,
    ) -> (Option<u64>, Option<u64>) {
        let (Some(rx), Some(tx)) = (rx, tx) else {
            return (None, None);
        };
        let now = Instant::now();
        let counters = TrafficCounters {
            rx_bytes: rx,
            tx_bytes: tx,
        };
        let rates = if let Some(prev) = self.devices.get(key) {
            let dt = now.duration_since(prev.at).as_secs_f64().max(0.001);
            (
                Some(((rx.saturating_sub(prev.counters.rx_bytes)) as f64 / dt) as u64),
                Some(((tx.saturating_sub(prev.counters.tx_bytes)) as f64 / dt) as u64),
            )
        } else {
            (None, None)
        };
        self.devices.insert(
            key.to_string(),
            Sample {
                counters,
                at: now,
            },
        );
        rates
    }
}
