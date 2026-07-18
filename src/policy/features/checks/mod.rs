//! Read-only classifiers available to policy bundles.
//!
//! Checks emit typed feature values only. They cannot apply effects and are
//! invoked exclusively when an applicable policy declares their feature name.

use std::sync::Arc;

use anyhow::Result;
use sqlx::PgPool;

use super::{FeatureProvider, media::NsfwMediaProvider, text::AutomodMatchProvider};
use crate::config::AppConfig;

/// OpenAI moderation is a check, not an engine dependency.
pub mod openai;

pub fn configured(db: PgPool, config: &AppConfig) -> Result<Vec<Arc<dyn FeatureProvider>>> {
    let mut providers: Vec<Arc<dyn FeatureProvider>> = vec![Arc::new(AutomodMatchProvider)];

    if config.nsfw_model_path.is_some() {
        providers.push(Arc::new(NsfwMediaProvider::new(db, config)?));
    }
    if let Some(api_key) = config.openai_api_key.clone() {
        providers.push(Arc::new(openai::OpenAiModerationProvider::new(
            api_key,
            config.openai_model.clone(),
            config.openai_connect_timeout,
            config.openai_request_timeout,
            config.openai_concurrency,
            config.openai_external_images,
        )?));
    }

    Ok(providers)
}
