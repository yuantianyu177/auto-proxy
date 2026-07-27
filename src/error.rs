use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApError {
    #[error("{code}: {message}")]
    Coded { code: String, message: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ApError {
    pub fn coded(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Coded {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Coded { code, .. } => code.as_str(),
            Self::Io(_) => "AP_IO_ERROR",
        }
    }
}

pub type Result<T> = std::result::Result<T, ApError>;
