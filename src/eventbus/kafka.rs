use super::{build_envelope, EventBus};
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;

pub struct KafkaEventBus {
    producer: FutureProducer,
    stream: String,
}

impl KafkaEventBus {
    pub fn new(brokers: &str, stream: String) -> anyhow::Result<Self> {
        let producer: FutureProducer = rdkafka::ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "5000")
            .create()?;
        Ok(Self { producer, stream })
    }
}

#[async_trait::async_trait]
impl EventBus for KafkaEventBus {
    async fn publish(&self, event_type: &str, data: serde_json::Value) -> anyhow::Result<()> {
        let event = build_envelope(event_type, data);
        let payload = serde_json::to_string(&event)?;

        let record = FutureRecord::to(&self.stream)
            .payload(&payload)
            .key("");

        self.producer
            .send(record, Duration::from_secs(0))
            .await
            .map_err(|(err, _msg)| anyhow::anyhow!("Kafka send error: {}", err))?;

        Ok(())
    }

    fn system_name(&self) -> &'static str {
        "kafka"
    }
}
