use std::{
    io::Cursor,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use futures::StreamExt;
use image::{DynamicImage, ImageFormat, ImageReader, Limits};
use image_hasher::{HashAlg, HasherConfig};
use ndarray::{Array, Array4, s};
use ort::session::Session;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::{
    FeatureProvider, ProviderCachePolicy, ProviderCategory, ProviderError, ProviderOutput,
};
use crate::{config::AppConfig, policy::model::Action};

pub struct SecureImageDownloader {
    allowed_hosts: Vec<String>,
    max_bytes: u64,
    max_pixels: u64,
}

impl SecureImageDownloader {
    pub fn new(allowed_hosts: Vec<String>, max_bytes: u64, max_pixels: u64) -> Self {
        Self {
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|host| !host.is_empty())
                .collect(),
            max_bytes,
            max_pixels,
        }
    }

    fn validate_url(&self, url: &reqwest::Url) -> Result<(String, u16), ProviderError> {
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err(ProviderError::Rejected);
        }
        let raw_host = url
            .host_str()
            .ok_or_else(|| ProviderError::InvalidInput("attachment URL has no host".into()))?;
        // A trailing-dot FQDN is equivalent for DNS but is easy to mismatch against
        // reqwest's resolver override key. Reject it rather than risk an unpinned lookup.
        if raw_host.ends_with('.') {
            return Err(ProviderError::Rejected);
        }
        let host = raw_host.to_ascii_lowercase();
        if !self
            .allowed_hosts
            .iter()
            .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
        {
            return Err(ProviderError::Rejected);
        }
        let port = url
            .port_or_known_default()
            .ok_or_else(|| ProviderError::InvalidInput("attachment URL has no port".into()))?;
        if port != 443 {
            return Err(ProviderError::Rejected);
        }
        Ok((host, port))
    }

    fn pinned_address(addresses: &[SocketAddr]) -> Result<SocketAddr, ProviderError> {
        let pinned = addresses.first().copied().ok_or(ProviderError::Rejected)?;
        // Reject the entire DNS answer if it contains a forbidden address. This
        // prevents a resolver from rotating a later private answer into use.
        if addresses.iter().any(|address| forbidden_ip(address.ip())) {
            return Err(ProviderError::Rejected);
        }
        Ok(pinned)
    }

    pub async fn fetch(&self, input: &str) -> Result<(Vec<u8>, ImageFormat), ProviderError> {
        let mut url = reqwest::Url::parse(input)
            .map_err(|_| ProviderError::InvalidInput("invalid attachment URL".into()))?;
        for redirect in 0..=3 {
            // This validation deliberately occurs inside the redirect loop so a
            // redirect cannot change scheme, credentials, host, or port unchecked.
            let (host, port) = self.validate_url(&url)?;
            let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| ProviderError::Unavailable)?
                .collect();
            let pinned = Self::pinned_address(&addresses)?;
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                // A system proxy would resolve the host again and defeat the DNS
                // validation/pinning above.
                .no_proxy()
                .connect_timeout(std::time::Duration::from_secs(2))
                .timeout(std::time::Duration::from_secs(10))
                .resolve(&host, pinned)
                .build()
                .map_err(|_| ProviderError::Internal)?;
            let response = client.get(url.clone()).send().await.map_err(|error| {
                if error.is_timeout() {
                    ProviderError::Timeout
                } else {
                    ProviderError::Unavailable
                }
            })?;
            if response.status().is_redirection() {
                if redirect == 3 {
                    return Err(ProviderError::Rejected);
                }
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(ProviderError::Rejected)?;
                url = url.join(location).map_err(|_| ProviderError::Rejected)?;
                continue;
            }
            if !response.status().is_success() {
                return Err(ProviderError::Rejected);
            }
            if response
                .content_length()
                .is_some_and(|length| length > self.max_bytes)
            {
                return Err(ProviderError::Rejected);
            }
            let mime = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .to_owned();
            let mut bytes = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| ProviderError::Unavailable)?;
                let next_length = (bytes.len() as u64)
                    .checked_add(chunk.len() as u64)
                    .ok_or(ProviderError::Rejected)?;
                if next_length > self.max_bytes {
                    return Err(ProviderError::Rejected);
                }
                bytes.extend_from_slice(&chunk);
            }
            let detected = validate_image_payload(&bytes, &mime, self.max_pixels)?;
            return Ok((bytes, detected));
        }
        Err(ProviderError::Rejected)
    }

    pub fn decode(&self, bytes: &[u8], format: ImageFormat) -> Result<DynamicImage, ProviderError> {
        if bytes.len() as u64 > self.max_bytes
            || image::guess_format(bytes).map_err(|_| ProviderError::Rejected)? != format
        {
            return Err(ProviderError::Rejected);
        }
        validate_dimensions(bytes, format, self.max_pixels)?;
        let max_dimension = self.max_pixels.min(u64::from(u32::MAX)) as u32;
        let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
        let mut limits = Limits::default();
        limits.max_image_width = Some(max_dimension);
        limits.max_image_height = Some(max_dimension);
        limits.max_alloc = Some(self.max_pixels.saturating_mul(4));
        reader.limits(limits);
        let image = reader.decode().map_err(|_| ProviderError::Rejected)?;
        if u64::from(image.width()) * u64::from(image.height()) > self.max_pixels {
            return Err(ProviderError::Rejected);
        }
        Ok(image)
    }
}

fn validate_image_payload(
    bytes: &[u8],
    declared_mime: &str,
    max_pixels: u64,
) -> Result<ImageFormat, ProviderError> {
    let declared = mime_format(declared_mime).ok_or(ProviderError::Rejected)?;
    let detected = image::guess_format(bytes).map_err(|_| ProviderError::Rejected)?;
    if detected != declared {
        return Err(ProviderError::Rejected);
    }
    validate_dimensions(bytes, detected, max_pixels)?;
    Ok(detected)
}

fn validate_dimensions(
    bytes: &[u8],
    format: ImageFormat,
    max_pixels: u64,
) -> Result<(u32, u32), ProviderError> {
    let (width, height) = ImageReader::with_format(Cursor::new(bytes), format)
        .into_dimensions()
        .map_err(|_| ProviderError::Rejected)?;
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(ProviderError::Rejected)?;
    if width == 0 || height == 0 || pixels > max_pixels {
        return Err(ProviderError::Rejected);
    }
    Ok((width, height))
}

fn mime_format(mime: &str) -> Option<ImageFormat> {
    match mime.trim().to_ascii_lowercase().as_str() {
        "image/jpeg" => Some(ImageFormat::Jpeg),
        "image/png" => Some(ImageFormat::Png),
        "image/webp" => Some(ImageFormat::WebP),
        "image/gif" => Some(ImageFormat::Gif),
        _ => None,
    }
}

fn forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                || a == 0
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19))
                || a >= 240
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            let octets = ip.octets();
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] == 0x0100
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0)
                || (segments[0] == 0x2001 && segments[1] == 0)
                || (segments[0] == 0x2001 && segments[1] == 2)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010)
                || (segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020)
                || segments[0] == 0x3ffe
                || (segments[0] & 0xfff0) == 0x3ff0
                || (octets[..12] == [0; 12] && ip.to_ipv4_mapped().is_none())
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| forbidden_ip(IpAddr::V4(mapped)))
                || (segments[0] == 0x0064
                    && segments[1] == 0xff9b
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0
                    && segments[5] == 0
                    && forbidden_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                        octets[12], octets[13], octets[14], octets[15],
                    ))))
                || (segments[0] == 0x2002
                    && forbidden_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                        octets[2], octets[3], octets[4], octets[5],
                    ))))
        }
    }
}

struct OnnxClassifier {
    session: Arc<Mutex<Session>>,
    input_name: String,
    image_size: u32,
    mean: [f32; 3],
    std: [f32; 3],
    labels: Vec<String>,
    version: String,
}

impl OnnxClassifier {
    fn new(config: &AppConfig) -> anyhow::Result<Self> {
        let path = config
            .nsfw_model_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("NSFW_MODEL_PATH is not configured"))?;
        let session = Session::builder()
            .map_err(|error| anyhow::anyhow!("failed to create ONNX session builder: {error}"))?
            .with_intra_threads(config.nsfw_model_threads)
            .map_err(|error| anyhow::anyhow!("failed to configure ONNX session: {error}"))?
            .commit_from_file(path)
            .map_err(|error| anyhow::anyhow!("failed to load ONNX model: {error}"))?;
        let input_name = session
            .inputs()
            .first()
            .map(|input| input.name().to_owned())
            .unwrap_or_else(|| config.nsfw_model_input_name.clone());
        let model_bytes = std::fs::read(path)?;
        Ok(Self {
            session: Arc::new(Mutex::new(session)),
            input_name,
            image_size: config.nsfw_model_image_size,
            mean: config.nsfw_model_mean,
            std: config.nsfw_model_std,
            labels: config.nsfw_model_labels.clone(),
            version: format!("onnx:{}", hex::encode(Sha256::digest(model_bytes))),
        })
    }

    async fn classify(&self, image: &DynamicImage) -> Result<(String, f64), ProviderError> {
        let tensor = preprocess(image, self.image_size, self.mean, self.std);
        let value = ort::value::Tensor::from_array(tensor).map_err(|_| ProviderError::Internal)?;
        let session = Arc::clone(&self.session);
        let input_name = self.input_name.clone();
        let logits = tokio::task::spawn_blocking(move || -> Result<Vec<f32>, ProviderError> {
            let mut session = session.lock().map_err(|_| ProviderError::Internal)?;
            let outputs = session
                .run(ort::inputs![input_name.as_str() => value])
                .map_err(|_| ProviderError::Internal)?;
            let (_, data) = outputs[0]
                .try_extract_tensor::<f32>()
                .map_err(|_| ProviderError::Internal)?;
            Ok(data.to_vec())
        })
        .await
        .map_err(|_| ProviderError::Internal)??;
        let probabilities = softmax(&logits);
        let (index, score) = probabilities
            .iter()
            .enumerate()
            .max_by(|left, right| left.1.total_cmp(right.1))
            .ok_or(ProviderError::Internal)?;
        Ok((
            self.labels
                .get(index)
                .cloned()
                .unwrap_or_else(|| format!("class_{index}")),
            f64::from(*score),
        ))
    }
}

fn preprocess(image: &DynamicImage, size: u32, mean: [f32; 3], std: [f32; 3]) -> Array4<f32> {
    let resized = image
        .resize_exact(size, size, image::imageops::FilterType::Lanczos3)
        .to_rgb8();
    let (width, height) = (resized.width() as usize, resized.height() as usize);
    let hwc = Array::from_shape_vec((height, width, 3), resized.into_raw())
        .expect("image dimensions are consistent")
        .mapv(|value| f32::from(value) / 255.0);
    let mut nchw = Array4::<f32>::zeros((1, 3, height, width));
    for channel in 0..3 {
        nchw.slice_mut(s![0, channel, .., ..]).assign(
            &hwc.slice(s![.., .., channel])
                .mapv(|value| (value - mean[channel]) / std[channel]),
        );
    }
    nchw
}

fn softmax(logits: &[f32]) -> Vec<f32> {
    let maximum = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exponentials: Vec<_> = logits.iter().map(|value| (value - maximum).exp()).collect();
    let sum: f32 = exponentials.iter().sum();
    exponentials.into_iter().map(|value| value / sum).collect()
}

#[derive(Serialize)]
struct MediaSignal {
    exact_hash: String,
    perceptual_hash: String,
    label: String,
    score: f64,
    model_version: String,
    cache_hit: bool,
    authoritative_override: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    override_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    override_version: Option<u64>,
}

pub struct NsfwMediaProvider {
    db: PgPool,
    downloader: SecureImageDownloader,
    classifier: OnnxClassifier,
    hasher: HasherConfig,
}

impl NsfwMediaProvider {
    pub fn new(db: PgPool, config: &AppConfig) -> anyhow::Result<Self> {
        Ok(Self {
            db,
            downloader: SecureImageDownloader::new(
                config.attachment_allowed_hosts.clone(),
                config.attachment_max_bytes,
                config.attachment_max_pixels,
            ),
            classifier: OnnxClassifier::new(config)?,
            hasher: HasherConfig::new()
                .hash_alg(HashAlg::DoubleGradient)
                .hash_size(16, 16),
        })
    }
}

#[async_trait]
impl FeatureProvider for NsfwMediaProvider {
    fn name(&self) -> &str {
        "media.nsfw"
    }
    fn version(&self) -> &str {
        &self.classifier.version
    }
    fn category(&self) -> ProviderCategory {
        ProviderCategory::Check
    }
    fn cache_policy(&self) -> ProviderCachePolicy {
        ProviderCachePolicy::ProviderManaged
    }
    async fn resolve(
        &self,
        action: &Action,
        _: &serde_json::Value,
    ) -> Result<ProviderOutput, ProviderError> {
        let urls = attachment_urls(action);
        let mut signals = Vec::new();
        for url in urls {
            let (bytes, format) = self.downloader.fetch(&url).await?;
            let exact_hash = hex::encode(Sha256::digest(&bytes));
            let image = self.downloader.decode(&bytes, format)?;
            let perceptual_hash = self.hasher.to_hasher().hash_image(&image).to_base64();
            let override_row = sqlx::query(
                "SELECT id, classification, version FROM trust_safety.nsfw_override \
                 WHERE exact_hash = $1 OR perceptual_hash = $2 \
                 ORDER BY (exact_hash = $1) DESC, updated_at DESC LIMIT 1",
            )
            .bind(&exact_hash)
            .bind(&perceptual_hash)
            .fetch_optional(&self.db)
            .await
            .map_err(|_| ProviderError::Unavailable)?;
            if let Some(row) = override_row {
                let classification: String = row
                    .try_get("classification")
                    .map_err(|_| ProviderError::Internal)?;
                let override_id = row
                    .try_get::<Uuid, _>("id")
                    .map_err(|_| ProviderError::Internal)?;
                let override_version = row
                    .try_get::<i64, _>("version")
                    .map_err(|_| ProviderError::Internal)?;
                signals.push(MediaSignal {
                    exact_hash,
                    perceptual_hash,
                    label: classification,
                    score: 1.0,
                    model_version: "authoritative-override".into(),
                    cache_hit: true,
                    authoritative_override: true,
                    override_id: Some(override_id.to_string()),
                    override_version: Some(override_version.max(0) as u64),
                });
                continue;
            }
            let cached = sqlx::query(
                "SELECT label, score, model_version FROM trust_safety.content_hash WHERE exact_hash = $1 AND model_version = $2"
            ).bind(&exact_hash).bind(&self.classifier.version).fetch_optional(&self.db).await.map_err(|_| ProviderError::Unavailable)?;
            if let Some(row) = cached {
                signals.push(MediaSignal {
                    exact_hash,
                    perceptual_hash,
                    label: row.try_get("label").map_err(|_| ProviderError::Internal)?,
                    score: row
                        .try_get::<Option<f64>, _>("score")
                        .map_err(|_| ProviderError::Internal)?
                        .unwrap_or(0.0),
                    model_version: row
                        .try_get("model_version")
                        .map_err(|_| ProviderError::Internal)?,
                    cache_hit: true,
                    authoritative_override: false,
                    override_id: None,
                    override_version: None,
                });
                continue;
            }
            let (label, score) = self.classifier.classify(&image).await?;
            sqlx::query(
                "INSERT INTO trust_safety.content_hash (exact_hash, perceptual_hash, media_type, label, score, model_version) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (exact_hash, model_version) DO NOTHING"
            ).bind(&exact_hash).bind(&perceptual_hash).bind(format_name(format)).bind(&label).bind(score).bind(&self.classifier.version)
            .execute(&self.db).await.map_err(|_| ProviderError::Unavailable)?;
            signals.push(MediaSignal {
                exact_hash,
                perceptual_hash,
                label,
                score,
                model_version: self.classifier.version.clone(),
                cache_hit: false,
                authoritative_override: false,
                override_id: None,
                override_version: None,
            });
        }
        Ok(ProviderOutput {
            value: serde_json::to_value(signals).map_err(|_| ProviderError::Internal)?,
            cache_hit: false,
            input_hash: None,
        })
    }

    fn redact_for_trace(&self, output: &ProviderOutput) -> serde_json::Value {
        redact_media_output(&output.value)
    }
}

fn redact_media_output(value: &serde_json::Value) -> serde_json::Value {
    serde_json::Value::Array(
        value
            .as_array()
            .into_iter()
            .flatten()
            .map(|signal| {
                serde_json::json!({
                    "label": signal.get("label"),
                    "score": signal.get("score"),
                    "model_version": signal.get("model_version"),
                    "cache_hit": signal.get("cache_hit"),
                    "authoritative_override": signal.get("authoritative_override"),
                    "override_id": signal.get("override_id"),
                    "override_version": signal.get("override_version"),
                })
            })
            .collect(),
    )
}

fn attachment_urls(action: &Action) -> Vec<String> {
    action
        .attributes
        .get("attachment_urls")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn format_name(format: ImageFormat) -> &'static str {
    match format {
        ImageFormat::Jpeg => "image/jpeg",
        ImageFormat::Png => "image/png",
        ImageFormat::WebP => "image/webp",
        ImageFormat::Gif => "image/gif",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn downloader(
        allowed_hosts: &[&str],
        max_bytes: u64,
        max_pixels: u64,
    ) -> SecureImageDownloader {
        SecureImageDownloader::new(
            allowed_hosts
                .iter()
                .map(|host| (*host).to_owned())
                .collect(),
            max_bytes,
            max_pixels,
        )
    }

    #[test]
    fn trace_redaction_removes_content_hashes_but_keeps_override_identity() {
        let redacted = redact_media_output(&serde_json::json!([{
            "exact_hash": "secret-exact",
            "perceptual_hash": "secret-perceptual",
            "label": "UNSAFE",
            "score": 1.0,
            "model_version": "authoritative-override",
            "cache_hit": true,
            "authoritative_override": true,
            "override_id": "override-1",
            "override_version": 3,
        }]));
        let item = &redacted[0];
        assert!(item.get("exact_hash").is_none());
        assert!(item.get("perceptual_hash").is_none());
        assert_eq!(item["override_id"], "override-1");
        assert_eq!(item["override_version"], 3);
    }

    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        DynamicImage::new_rgba8(width, height)
            .write_to(&mut output, ImageFormat::Png)
            .expect("test image encodes");
        output.into_inner()
    }

    #[test]
    fn approved_host_policy_accepts_exact_and_subdomain_only() {
        let downloader = downloader(&[" CDN.Example.COM. "], 1024, 1024);

        assert!(
            downloader
                .validate_url(&reqwest::Url::parse("https://cdn.example.com/image.png").unwrap())
                .is_ok()
        );
        assert!(
            downloader
                .validate_url(
                    &reqwest::Url::parse("https://images.cdn.example.com/image.png").unwrap()
                )
                .is_ok()
        );
        assert!(
            downloader
                .validate_url(
                    &reqwest::Url::parse("https://cdn.example.com.evil.test/image.png").unwrap()
                )
                .is_err()
        );
    }

    #[test]
    fn every_redirect_target_is_revalidated() {
        let downloader = downloader(&["cdn.example.com"], 1024, 1024);
        let original = reqwest::Url::parse("https://cdn.example.com/image.png").unwrap();
        let allowed = original
            .join("https://assets.cdn.example.com/next.png")
            .unwrap();
        let disallowed = original.join("https://evil.test/next.png").unwrap();
        let downgrade = original.join("http://cdn.example.com/next.png").unwrap();
        let credentials = original
            .join("https://user:secret@cdn.example.com/next.png")
            .unwrap();
        let alternate_port = original
            .join("https://cdn.example.com:8443/next.png")
            .unwrap();

        assert!(downloader.validate_url(&original).is_ok());
        assert!(downloader.validate_url(&allowed).is_ok());
        assert!(downloader.validate_url(&disallowed).is_err());
        assert!(downloader.validate_url(&downgrade).is_err());
        assert!(downloader.validate_url(&credentials).is_err());
        assert!(downloader.validate_url(&alternate_port).is_err());
    }

    #[test]
    fn mixed_dns_answer_is_rejected_instead_of_rotated() {
        let public = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);
        let private = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

        assert_eq!(
            SecureImageDownloader::pinned_address(&[public]).unwrap(),
            public
        );
        assert!(SecureImageDownloader::pinned_address(&[public, private]).is_err());
        assert!(SecureImageDownloader::pinned_address(&[private, public]).is_err());
        assert!(SecureImageDownloader::pinned_address(&[]).is_err());
    }

    #[test]
    fn rejects_private_and_reserved_addresses() {
        let forbidden = [
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "fc00::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "fec0::1".parse().unwrap(),
            "100::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "2001:2::1".parse().unwrap(),
            "3fff::1".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
            "64:ff9b::127.0.0.1".parse().unwrap(),
            "2002:7f00:1::1".parse().unwrap(),
        ];
        for address in forbidden {
            assert!(forbidden_ip(address), "expected {address} to be forbidden");
        }

        assert!(!forbidden_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!forbidden_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(!forbidden_ip("64:ff9b::8.8.8.8".parse().unwrap()));
        assert!(!forbidden_ip("2002:0808:0808::1".parse().unwrap()));
    }

    #[test]
    fn rejects_invalid_or_mismatched_mime_and_decoded_format() {
        let bytes = png(2, 2);
        let downloader = downloader(&["cdn.example.com"], bytes.len() as u64, 4);

        assert!(validate_image_payload(&bytes, "application/octet-stream", 4).is_err());
        assert!(validate_image_payload(&bytes, "image/jpeg", 4).is_err());
        assert!(validate_image_payload(b"not an image", "image/png", 4).is_err());
        assert!(downloader.decode(&bytes, ImageFormat::Jpeg).is_err());
        assert!(validate_image_payload(&bytes, " IMAGE/PNG ", 4).is_ok());
    }

    #[test]
    fn byte_limit_is_enforced_again_during_decode() {
        let bytes = png(2, 2);
        let downloader = downloader(&["cdn.example.com"], bytes.len() as u64 - 1, 4);

        assert!(downloader.decode(&bytes, ImageFormat::Png).is_err());
    }

    #[test]
    fn pixel_limit_rejects_highly_compressible_image_bomb() {
        let bytes = png(512, 512);
        assert!(
            bytes.len() < 512 * 512,
            "fixture should be highly compressed"
        );
        let downloader = downloader(&["cdn.example.com"], bytes.len() as u64, 10_000);

        assert!(validate_image_payload(&bytes, "image/png", 10_000).is_err());
        assert!(downloader.decode(&bytes, ImageFormat::Png).is_err());
    }

    #[test]
    fn valid_image_within_byte_pixel_and_allocation_limits_decodes() {
        let bytes = png(16, 16);
        let downloader = downloader(&["cdn.example.com"], bytes.len() as u64, 256);

        let decoded = downloader
            .decode(&bytes, ImageFormat::Png)
            .expect("bounded image decodes");
        assert_eq!((decoded.width(), decoded.height()), (16, 16));
    }
}
