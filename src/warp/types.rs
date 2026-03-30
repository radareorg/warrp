#[derive(Debug, Clone)]
pub struct Target {
    pub architecture: String,
    pub platform: String,
}

impl Target {
    pub fn new(architecture: String, platform: String) -> Self {
        Self { architecture, platform }
    }
    
    pub fn matches(&self, other: &Target) -> bool {
        // Architecture must match exactly
        // Platform can be more flexible
        if self.architecture != other.architecture {
            return false;
        }
        
        // If either platform is empty/wildcard, consider it a match
        if self.platform.is_empty() || other.platform.is_empty() {
            return true;
        }
        
        self.platform == other.platform
    }
}

impl Default for Target {
    fn default() -> Self {
        Self {
            architecture: "unknown".to_string(),
            platform: "unknown".to_string(),
        }
    }
}