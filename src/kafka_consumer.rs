use std::sync::Arc;

use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer as RdkafkaStreamConsumer};
use rdkafka::{ClientConfig, Message};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, instrument, warn};

use crate::config::AppConfig;
use crate::health::HealthState;
use crate::pipeline::{Pipeline, PipelineOutput};

/// Kafka consumer that pulls jobs and dispatches them to the pipeline.
pub struct StreamConsumer {
    pipeline: Arc<Pipeline>,
    config: AppConfig,
    _health: Arc<HealthState>,
    cancel: CancellationToken,
}

impl StreamConsumer {
    pub fn new(
        pipeline: Arc<Pipeline>,
        config: AppConfig,
        health: Arc<HealthState>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            pipeline,
            config,
            _health: health,
            cancel,
        }
    }

    /// Run the main consumer loop until cancellation.
    #[instrument(skip(self), name = "consumer_loop")]
    pub async fn run(&self) -> anyhow::Result<()> {
        let consumer: RdkafkaStreamConsumer = ClientConfig::new()
            .set("group.id", &self.config.kafka_group_id)
            .set("bootstrap.servers", &self.config.kafka_brokers)
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .set("client.id", &self.config.consumer_name)
            .create()
            .map_err(|e| anyhow::anyhow!("failed to create kafka consumer: {e}"))?;

        consumer
            .subscribe(&[&self.config.kafka_jobs_topic])
            .map_err(|e| anyhow::anyhow!("failed to subscribe to jobs topic: {e}"))?;

        info!(
            brokers = %self.config.kafka_brokers,
            topic = %self.config.kafka_jobs_topic,
            group = %self.config.kafka_group_id,
            consumer = %self.config.consumer_name,
            "entering consumer loop"
        );

        let consumer = Arc::new(consumer);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.worker_count));

        loop {
            if self.cancel.is_cancelled() {
                info!("cancellation received — exiting consumer loop");
                break;
            }

            let msg_result = tokio::select! {
                res = consumer.recv() => res,
                _ = self.cancel.cancelled() => {
                    info!("cancellation received while waiting for message — exiting consumer loop");
                    break;
                }
            };

            let borrowed_message = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    error!(error = %e, "Kafka error receiving message");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            let payload = match borrowed_message.payload_view::<str>() {
                None => {
                    warn!("empty payload — skipping");
                    let _ = consumer.commit_message(&borrowed_message, CommitMode::Async);
                    continue;
                }
                Some(Ok(s)) => s.to_owned(),
                Some(Err(e)) => {
                    error!(error = %e, "failed to deserialize message payload as string");
                    let _ = consumer.commit_message(&borrowed_message, CommitMode::Async);
                    continue;
                }
            };

            let url = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&payload) {
                if let Some(u) = json.get("url").and_then(|u| u.as_str()) {
                    u.to_owned()
                } else {
                    warn!(payload = %payload, "JSON missing 'url' field — skipping");
                    let _ = consumer.commit_message(&borrowed_message, CommitMode::Async);
                    continue;
                }
            } else {
                payload
            };

            let topic = borrowed_message.topic().to_owned();
            let partition = borrowed_message.partition();
            let offset = borrowed_message.offset();

            let permit = Arc::clone(&semaphore).acquire_owned().await;
            let pipeline = Arc::clone(&self.pipeline);
            let consumer_clone = Arc::clone(&consumer);

            tokio::spawn(async move {
                let _permit = permit; // held until task completes

                match pipeline.process(&url).await {
                    Ok(output) => {
                        if let Err(e) = publish_result(&pipeline, &output).await {
                            error!(error = %e, url = %url, "failed to publish result");
                        }
                    }
                    Err(e) => {
                        error!(error = %e, url = %url, "pipeline failed");
                        // TODO: dead-letter queue
                    }
                }

                let mut tpl = rdkafka::TopicPartitionList::new();
                let _ = tpl.add_partition_offset(
                    &topic,
                    partition,
                    rdkafka::Offset::Offset(offset + 1),
                );
                if let Err(e) = consumer_clone.commit(&tpl, CommitMode::Async) {
                    warn!(error = %e, "failed to commit message");
                }
            });
        }

        info!("waiting for in-flight workers to drain");
        let _ = semaphore
            .acquire_many(self.config.worker_count as u32)
            .await;
        info!("all workers drained");

        Ok(())
    }
}

/// Push the pipeline output as a CloudEvent to the event bus.
async fn publish_result(
    pipeline: &Pipeline,
    output: &PipelineOutput,
) -> anyhow::Result<()> {
    let event_data = serde_json::json!({
        "url": output.url,
        "safe": output.label != "nsfw",
        "labels": [&output.label],
        "score": output.score,
        "phash": output.phash,
        "xxh3": output.xxh3,
    });

    if let Err(e) = pipeline.eventbus.publish(
        "fun.interchat.polarizer.result.ready",
        event_data,
    )
    .await
    {
        warn!(error = %e, url = %output.url, "failed to publish CloudEvent");
        return Err(e);
    }

    info!(
        url = %output.url,
        score = output.score,
        label = %output.label,
        cache_hit = output.cache_hit,
        elapsed_ms = output.elapsed_ms,
        "processed image and published result"
    );

    Ok(())
}
