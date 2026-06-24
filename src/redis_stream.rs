use std::sync::Arc;

use redis::AsyncCommands;
use redis::streams::{StreamReadOptions, StreamReadReply};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, warn};

use crate::config::AppConfig;
use crate::health::HealthState;
use crate::pipeline::{Pipeline, PipelineOutput};

/// Redis Streams consumer that pulls jobs and dispatches them to the pipeline.
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

    /// Ensure the consumer group exists (idempotent).
    async fn ensure_group(&self) -> anyhow::Result<()> {
        let mut conn = self.pipeline.redis.clone();

        // XGROUP CREATE <stream> <group> 0 MKSTREAM
        // This is idempotent — if the group already exists, Redis returns BUSYGROUP
        // which we intentionally ignore.
        let result: Result<(), redis::RedisError> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(&self.config.stream_key)
            .arg(&self.config.consumer_group)
            .arg("0")
            .arg("MKSTREAM")
            .query_async(&mut conn)
            .await;

        match result {
            Ok(()) => info!(
                stream = %self.config.stream_key,
                group = %self.config.consumer_group,
                "consumer group created"
            ),
            Err(e) if e.to_string().contains("BUSYGROUP") => {
                debug!(
                    group = %self.config.consumer_group,
                    "consumer group already exists"
                );
            }
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }

    /// Run the main consumer loop until cancellation.
    #[instrument(skip(self), name = "consumer_loop")]
    pub async fn run(&self) -> anyhow::Result<()> {
        self.ensure_group().await?;

        let opts = StreamReadOptions::default()
            .group(&self.config.consumer_group, &self.config.consumer_name)
            .count(self.config.batch_size)
            .block(self.config.block_timeout.as_millis() as usize);

        info!(
            stream = %self.config.stream_key,
            group = %self.config.consumer_group,
            consumer = %self.config.consumer_name,
            batch_size = self.config.batch_size,
            "entering consumer loop"
        );

        // Semaphore to cap concurrent worker tasks.
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.worker_count));

        // Create a DEDICATED connection for the blocking XREADGROUP command.
        // If we share the pipeline.redis connection, the BLOCK command will stall
        // the entire multiplexed connection, causing cache GET/SETs to hang for 5s!
        let client = redis::Client::open(self.config.redis_uri.as_str())
            .map_err(|e| anyhow::anyhow!("failed to create redis client: {e}"))?;
        let mut read_conn = client
            .get_connection_manager()
            .await
            .map_err(|e| anyhow::anyhow!("failed to create dedicated read connection: {e}"))?;

        loop {
            if self.cancel.is_cancelled() {
                info!("cancellation received — exiting consumer loop");
                break;
            }

            // ">" means read only new, never-delivered messages.
            let reply: StreamReadReply = match read_conn
                .xread_options(&[&self.config.stream_key], &[">"], &opts)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    error!(error = %e, "XREADGROUP failed");
                    // Back off briefly to avoid tight-looping on transient errors.
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            for key in &reply.keys {
                for msg in &key.ids {
                    let msg_id = msg.id.clone();

                    // Extract the image URL from the stream entry.
                    let url: Option<String> = msg.get("url");

                    let Some(url) = url else {
                        warn!(msg_id = %msg_id, "message missing 'url' field — acknowledging and skipping");
                        let mut xack_conn = self.pipeline.redis.clone();
                        let _: Result<(), _> = xack_conn
                            .xack(
                                &self.config.stream_key,
                                &self.config.consumer_group,
                                &[&msg_id],
                            )
                            .await;
                        continue;
                    };

                    // Acquire semaphore permit before spawning.
                    let permit = Arc::clone(&semaphore).acquire_owned().await;
                    let pipeline = Arc::clone(&self.pipeline);
                    let stream_key = self.config.stream_key.clone();
                    let result_key = self.config.result_stream_key.clone();
                    let group = self.config.consumer_group.clone();

                    tokio::spawn(async move {
                        let _permit = permit; // held until task completes

                        match pipeline.process(&url).await {
                            Ok(output) => {
                                if let Err(e) =
                                    publish_result(&pipeline, &result_key, &output).await
                                {
                                    error!(error = %e, msg_id = %msg_id, "failed to publish result");
                                }
                            }
                            Err(e) => {
                                error!(error = %e, url = %url, msg_id = %msg_id, "pipeline failed");
                                // TODO: push to a dead-letter stream for retry / inspection.
                            }
                        }

                        // Acknowledge regardless — failed messages should go to DLQ, not block the stream.
                        let mut conn = pipeline.redis.clone();
                        let _: Result<(), _> = conn.xack(&stream_key, &group, &[&msg_id]).await;
                    });
                }
            }
        }

        // Wait for all in-flight tasks to complete.
        info!("waiting for in-flight workers to drain");
        let _ = semaphore
            .acquire_many(self.config.worker_count as u32)
            .await;
        info!("all workers drained");

        Ok(())
    }
}

/// Push the pipeline output to the results stream.
async fn publish_result(
    pipeline: &Pipeline,
    result_key: &str,
    output: &PipelineOutput,
) -> anyhow::Result<()> {
    let mut conn = pipeline.redis.clone();

    let payload = serde_json::to_string(output)?;

    let mut pipe = redis::pipe();
    pipe.atomic()
        .cmd("XADD")
        .arg(result_key)
        .arg("MAXLEN")
        .arg("~")
        .arg(10000)
        .arg("*")
        .arg("url")
        .arg(output.url.as_str())
        .arg("xxh3")
        .arg(output.xxh3.as_str())
        .arg("phash")
        .arg(output.phash.as_str())
        .arg("score")
        .arg(output.score.to_string())
        .arg("label")
        .arg(output.label.as_str())
        .arg("cache_hit")
        .arg(output.cache_hit.to_string())
        .arg("elapsed_ms")
        .arg(output.elapsed_ms.to_string())
        .arg("payload")
        .arg(&payload)
        .cmd("PUBLISH")
        .arg(format!("polarizer:events:{}", output.url))
        .arg(&payload);

    let _: () = pipe.query_async(&mut conn).await?;

    // Also publish as CloudEvent on the inter-service event bus.
    let event_data = serde_json::json!({
        "url": output.url,
        "safe": output.label != "nsfw",
        "labels": [&output.label],
    });
    if let Err(e) = pipeline.eventbus.publish(
        "fun.interchat.polarizer.result.ready",
        event_data,
    )
    .await
    {
        warn!(error = %e, url = %output.url, "failed to publish CloudEvent");
    }

    info!(
        result_key,
        url = %output.url,
        score = output.score,
        label = %output.label,
        cache_hit = output.cache_hit,
        elapsed_ms = output.elapsed_ms,
        "processed image and published result"
    );

    Ok(())
}
