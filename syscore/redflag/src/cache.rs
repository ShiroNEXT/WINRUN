use crate::apps::AppsResponse;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

/// Cache manager for installed apps
pub struct AppsCache {
    cache_path: PathBuf,
    cached_data: Option<AppsResponse>,
}

impl AppsCache {
    /// Create a new cache instance
    pub fn new() -> Self {
        let cache_path = Self::get_cache_path();
        
        // Try to load existing cache
        let cached_data = Self::load_from_file(&cache_path).ok();
        
        if cached_data.is_some() {
            log::info!("Loaded apps cache from file");
        }
        
        AppsCache {
            cache_path,
            cached_data,
        }
    }

    /// Get the cache file path
    fn get_cache_path() -> PathBuf {
        // Use ProgramData on Windows for service data
        if let Ok(program_data) = std::env::var("ProgramData") {
            let path = PathBuf::from(program_data)
                .join("WinRun")
                .join("apps_cache.json");
            
            // Ensure directory exists
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            
            return path;
        }
        
        // Fallback to temp directory
        let path = std::env::temp_dir()
            .join("winrun_apps_cache.json");
        
        path
    }

    /// Load cache from file
    fn load_from_file(path: &PathBuf) -> Result<AppsResponse> {
        let content = fs::read_to_string(path)
            .context("Failed to read cache file")?;
        
        let apps_response: AppsResponse = serde_json::from_str(&content)
            .context("Failed to parse cache file")?;
        
        log::info!("Loaded {} apps from cache file", apps_response.apps.len());
        Ok(apps_response)
    }

    /// Save apps to cache file
    pub fn save_apps(&mut self, apps_response: &AppsResponse) -> Result<()> {
        // Save to file
        let json = serde_json::to_string_pretty(apps_response)
            .context("Failed to serialize apps to JSON")?;
        
        fs::write(&self.cache_path, json)
            .context("Failed to write cache file")?;
        
        // Update in-memory cache
        self.cached_data = Some(AppsResponse {
            apps: apps_response.apps.clone(),
        });
        
        log::info!("Saved {} apps to cache file at {:?}", apps_response.apps.len(), self.cache_path);
        Ok(())
    }

    /// Get cached apps
    pub fn get_apps(&self) -> Result<AppsResponse> {
        if let Some(ref cached) = self.cached_data {
            return Ok(AppsResponse {
                apps: cached.apps.clone(),
            });
        }
        
        // Try to load from file if not in memory
        match Self::load_from_file(&self.cache_path) {
            Ok(apps) => Ok(apps),
            Err(_) => {
                // Return empty list if no cache available
                log::warn!("No cache available, returning empty app list");
                Ok(AppsResponse { apps: vec![] })
            }
        }
    }

    /// Clear cache
    pub fn clear_cache(&mut self) -> Result<()> {
        self.cached_data = None;
        
        if self.cache_path.exists() {
            fs::remove_file(&self.cache_path)
                .context("Failed to delete cache file")?;
        }
        
        log::info!("Cache cleared");
        Ok(())
    }

    /// Get cache file path for external access
    pub fn cache_file_path() -> PathBuf {
        Self::get_cache_path()
    }
}

impl Default for AppsCache {
    fn default() -> Self {
        Self::new()
    }
}
