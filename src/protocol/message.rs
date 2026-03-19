use std::collections::HashMap;

/// IRC message as specified by Modern IRC and message-tags extension.
/// Format: ['@' tags SPACE] [':' prefix SPACE] command params CRLF
#[derive(Debug, Clone)]
pub struct Message {
    /// Optional message tags (@key=value;key2...)
    pub tags: HashMap<String, Option<String>>,
    /// Optional source/prefix (servername or nick!user@host)
    pub prefix: Option<String>,
    /// Command (uppercase for IRC commands, or custom)
    pub command: String,
    /// Parameters (last param may have leading ':' for trailing)
    pub params: Vec<String>,
}

impl Message {
    pub fn new(command: impl Into<String>, params: Vec<String>) -> Self {
        Self {
            tags: HashMap::new(),
            prefix: None,
            command: command.into().to_uppercase(),
            params,
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn with_tags(mut self, tags: HashMap<String, Option<String>>) -> Self {
        self.tags = tags;
        self
    }

    pub fn add_tag(&mut self, key: impl Into<String>, value: Option<String>) {
        self.tags.insert(key.into(), value);
    }

    /// Get trailing parameter (last param, may contain spaces)
    pub fn trailing(&self) -> Option<&str> {
        self.params.last().map(|s| s.as_str())
    }

    /// Raw message length for size limit checks (excluding CRLF)
    pub fn raw_len(&self) -> usize {
        let serialized = super::format::format_message(self);
        serialized.len()
    }
}
