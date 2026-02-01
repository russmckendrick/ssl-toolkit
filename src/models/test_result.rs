//! Test result types for verbose output

use super::CertificateSummary;
use serde::Serialize;

/// Status of a check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
}

impl CheckStatus {
    /// Get the icon for this status
    pub fn icon(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "✓",
            CheckStatus::Warning => "⚠",
            CheckStatus::Fail => "✗",
        }
    }

    /// Get the color name for this status
    pub fn color_name(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "green",
            CheckStatus::Warning => "yellow",
            CheckStatus::Fail => "red",
        }
    }
}

/// A single test step within a check
#[derive(Debug, Clone, Serialize)]
pub struct TestStep {
    /// Step description
    pub description: String,
    /// Step status
    pub status: CheckStatus,
    /// Additional details
    pub details: Option<String>,
}

impl TestStep {
    /// Create a new passing test step
    pub fn pass(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            status: CheckStatus::Pass,
            details: None,
        }
    }

    /// Create a new warning test step
    pub fn warning(description: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            status: CheckStatus::Warning,
            details: Some(details.into()),
        }
    }

    /// Create a new failing test step
    pub fn fail(description: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            status: CheckStatus::Fail,
            details: Some(details.into()),
        }
    }
}

/// A section of detailed information
#[derive(Debug, Clone, Serialize)]
pub enum DetailSection {
    /// Key-value pairs
    KeyValue {
        title: Option<String>,
        pairs: Vec<(String, String)>,
    },
    /// Tabular data
    Table {
        title: Option<String>,
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    /// Simple list
    List {
        title: Option<String>,
        items: Vec<String>,
    },
    /// Free-form text
    Text {
        title: Option<String>,
        content: String,
    },
    /// Certificate chain visualization
    CertificateChain {
        certificates: Vec<CertificateSummary>,
    },
}

impl DetailSection {
    /// Create a key-value section
    pub fn key_value(title: Option<String>, pairs: Vec<(String, String)>) -> Self {
        Self::KeyValue { title, pairs }
    }

    /// Create a table section
    pub fn table(title: Option<String>, headers: Vec<String>, rows: Vec<Vec<String>>) -> Self {
        Self::Table {
            title,
            headers,
            rows,
        }
    }

    /// Create a list section
    pub fn list(title: Option<String>, items: Vec<String>) -> Self {
        Self::List { title, items }
    }

    /// Create a text section
    pub fn text(title: Option<String>, content: String) -> Self {
        Self::Text { title, content }
    }

    /// Create a certificate chain section
    pub fn certificate_chain(certificates: Vec<CertificateSummary>) -> Self {
        Self::CertificateChain { certificates }
    }
}

/// Complete test result
#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    /// Test title/header
    pub title: String,
    /// Overall status
    pub status: CheckStatus,
    /// One-line summary
    pub summary: String,
    /// Detailed sections
    pub details: Vec<DetailSection>,
    /// Individual test steps
    pub test_steps: Vec<TestStep>,
    /// Recommendations for improvement
    pub recommendations: Vec<String>,
}

impl TestResult {
    /// Create a new test result
    pub fn new(title: impl Into<String>, status: CheckStatus, summary: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            status,
            summary: summary.into(),
            details: vec![],
            test_steps: vec![],
            recommendations: vec![],
        }
    }

    /// Add a detail section
    pub fn with_detail(mut self, section: DetailSection) -> Self {
        self.details.push(section);
        self
    }

    /// Add a test step
    pub fn with_step(mut self, step: TestStep) -> Self {
        self.test_steps.push(step);
        self
    }

    /// Add a recommendation
    pub fn with_recommendation(mut self, recommendation: impl Into<String>) -> Self {
        self.recommendations.push(recommendation.into());
        self
    }
}
