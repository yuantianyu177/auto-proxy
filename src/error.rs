use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApError {
    #[error("{code}: {message}")]
    Coded { code: &'static str, message: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ApError {
    pub fn coded(code: &'static str, message: impl Into<String>) -> Self {
        Self::Coded {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Coded { code, .. } => code,
            Self::Io(_) => "AP_IO_ERROR",
            Self::Other(_) => "AP_ERROR",
        }
    }
}

pub type Result<T> = std::result::Result<T, ApError>;
