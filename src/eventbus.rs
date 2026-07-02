use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use uuid::Uuid;

/// CloudEvents v1.0 envelope for inter-service events.
#[derive(Debug, Serialize)]
pub struct CloudEvent {
    pub specversion: &'static str,
    #[serde(rename = "type")]
    pub event_type: String,
    pub source: &'static str,
    pub id: String,
    pub time: String,
    pub datacontenttype: &'static str,
    pub data: serde_json::Value,
}

const SOURCE: &str = "/polarizer";

fn generate_id() -> String {
    format!("evt_{}", Uuid::new_v4().simple())
}

fn format_utc_rfc3339() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs();

    let secs = total_secs % 86_400;
    let days = total_secs / 86_400;

    let hour = secs / 3600;
    let min = (secs % 3600) / 60;
    let sec = secs % 60;

    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

pub fn build_envelope(event_type: &str, data: serde_json::Value) -> CloudEvent {
    CloudEvent {
        specversion: "1.0",
        event_type: event_type.to_string(),
        source: SOURCE,
        id: generate_id(),
        time: format_utc_rfc3339(),
        datacontenttype: "application/json",
        data,
    }
}

/// Async trait for publishing CloudEvents to the inter-service event bus.
#[async_trait::async_trait]
pub trait EventBus: Send + Sync {
    /// Build a CloudEvent envelope and publish it to the configured stream/topic.
    async fn publish(&self, event_type: &str, data: serde_json::Value) -> anyhow::Result<()>;
    /// Returns the transport backend name for OpenTelemetry messaging.system attribute.
    #[allow(dead_code)]
    fn system_name(&self) -> &'static str;
}



/// Kafka implementation of the `EventBus` trait.
pub struct KafkaEventBus {
    producer: rdkafka::producer::FutureProducer,
    topic: String,
}

impl KafkaEventBus {
    pub fn new(brokers: &str, topic: String) -> anyhow::Result<Self> {
        let producer: rdkafka::producer::FutureProducer = rdkafka::ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "5000")
            .create()?;
        Ok(Self { producer, topic })
    }
}

#[async_trait::async_trait]
impl EventBus for KafkaEventBus {
    async fn publish(&self, event_type: &str, data: serde_json::Value) -> anyhow::Result<()> {
        let event = build_envelope(event_type, data);
        let payload = serde_json::to_string(&event)?;

        let record = rdkafka::producer::FutureRecord::to(&self.topic)
            .key("")
            .payload(&payload);

        let _ = self.producer.send(record, std::time::Duration::from_secs(0)).await
            .map_err(|(e, _)| anyhow::anyhow!("failed to publish event: {}", e))?;

        Ok(())
    }

    #[allow(dead_code)]
    fn system_name(&self) -> &'static str { "kafka" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct MockEventBus {
        calls: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
    }

    impl MockEventBus {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> Arc<Mutex<Vec<(String, serde_json::Value)>>> {
            self.calls.clone()
        }
    }

    #[async_trait::async_trait]
    impl EventBus for MockEventBus {
        async fn publish(
            &self,
            event_type: &str,
            data: serde_json::Value,
        ) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push((event_type.to_string(), data));
            Ok(())
        }

        fn system_name(&self) -> &'static str {
            "mock"
        }
    }

    #[test]
    fn test_build_envelope_produces_valid_cloud_event() {
        let data = serde_json::json!({"key": "value"});
        let event = build_envelope("fun.interchat.test", data.clone());

        assert_eq!(event.specversion, "1.0");
        assert_eq!(event.source, "/polarizer");
        assert_eq!(event.event_type, "fun.interchat.test");
        assert_eq!(event.datacontenttype, "application/json");
        assert_eq!(event.data, data);

        assert!(
            event.id.starts_with("evt_"),
            "Event ID should start with 'evt_', got: {}",
            event.id
        );
        assert_eq!(
            event.id.len(),
            36,
            "Event ID should be 36 chars (evt_ + 32 hex), got {} chars: {}",
            event.id.len(),
            event.id
        );

        assert!(
            event.time.ends_with('Z'),
            "Time should end with 'Z', got: {}",
            event.time
        );
        assert_eq!(
            event.time.len(),
            20,
            "Time should be 20 chars (YYYY-MM-DDTHH:MM:SSZ), got: {}",
            event.time
        );
    }

    #[test]
    fn test_generate_id_format() {
        let id1 = generate_id();
        let id2 = generate_id();

        assert!(id1.starts_with("evt_"));
        assert_eq!(id1.len(), 36);
        assert_eq!(id2.len(), 36);

        assert_ne!(id1, id2, "Generated IDs should be unique");

        let hex_part = &id1[4..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "Hex part should only contain hex digits, got: {}", hex_part);
    }

    #[test]
    fn test_format_utc_rfc3339_format() {
        let ts = format_utc_rfc3339();

        assert_eq!(ts.len(), 20, "Expected 20 chars, got: '{}'", ts);
        assert!(ts.ends_with('Z'), "Should end with Z, got: '{}'", ts);

        let parts: Vec<&str> = ts.trim_end_matches('Z').splitn(2, 'T').collect();
        assert_eq!(parts.len(), 2);

        let date_parts: Vec<&str> = parts[0].splitn(3, '-').collect();
        assert_eq!(date_parts.len(), 3);
        assert!(date_parts[0].parse::<u32>().is_ok(), "Year should be numeric");
        assert!(date_parts[1].parse::<u32>().is_ok(), "Month should be numeric");
        assert!(date_parts[2].parse::<u32>().is_ok(), "Day should be numeric");

        let time_parts: Vec<&str> = parts[1].splitn(3, ':').collect();
        assert_eq!(time_parts.len(), 3);
        let hour: u32 = time_parts[0].parse().unwrap();
        let min: u32 = time_parts[1].parse().unwrap();
        let sec: u32 = time_parts[2].parse().unwrap();
        assert!(hour < 24, "Hour out of range: {}", hour);
        assert!(min < 60, "Minute out of range: {}", min);
        assert!(sec < 60, "Second out of range: {}", sec);
    }

    #[test]
    fn test_build_envelope_json_serializable() {
        let data = serde_json::json!({"key": "value"});
        let event = build_envelope("fun.interchat.test", data);

        let serialized = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();

        assert_eq!(parsed["specversion"], "1.0");
        assert_eq!(parsed["source"], "/polarizer");
        assert_eq!(parsed["type"], "fun.interchat.test");
        assert_eq!(parsed["datacontenttype"], "application/json");
        assert!(parsed["id"].is_string());
        assert!(parsed["time"].is_string());
    }

    #[test]
    fn test_build_envelope_id_uniqueness() {
        let mut ids = Vec::new();
        for _ in 0..100 {
            let event = build_envelope("fun.interchat.test", serde_json::json!({}));
            ids.push(event.id);
        }
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "All 100 IDs should be unique");
    }

    #[tokio::test]
    async fn test_mock_event_bus_publish() {
        let bus = MockEventBus::new();
        let calls = bus.calls();

        let data = serde_json::json!({"event": "test"});
        bus.publish("fun.interchat.test", data.clone()).await.unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, "fun.interchat.test");
        assert_eq!(recorded[0].1, data);
    }

    #[test]
    fn test_civil_from_days_known_date() {
        let (y, m, d) = civil_from_days(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);

        let (y, m, d) = civil_from_days(7305);
        assert_eq!(y, 1990);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }
}
