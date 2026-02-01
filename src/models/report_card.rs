//! Report card with overall grade

use super::{CheckStatus, TestResult};
use serde::Serialize;

/// Overall grade for the SSL/TLS configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Grade {
    APlus,
    A,
    AMinus,
    BPlus,
    B,
    BMinus,
    CPlus,
    C,
    CMinus,
    D,
    F,
}

impl Grade {
    /// Get the display string for this grade
    pub fn as_str(&self) -> &'static str {
        match self {
            Grade::APlus => "A+",
            Grade::A => "A",
            Grade::AMinus => "A-",
            Grade::BPlus => "B+",
            Grade::B => "B",
            Grade::BMinus => "B-",
            Grade::CPlus => "C+",
            Grade::C => "C",
            Grade::CMinus => "C-",
            Grade::D => "D",
            Grade::F => "F",
        }
    }

    /// Get the color for this grade
    pub fn color(&self) -> &'static str {
        match self {
            Grade::APlus | Grade::A => "#10B981",
            Grade::AMinus | Grade::BPlus => "#34D399",
            Grade::B => "#FCD34D",
            Grade::BMinus | Grade::CPlus => "#FBBF24",
            Grade::C => "#F59E0B",
            Grade::CMinus | Grade::D => "#F97316",
            Grade::F => "#EF4444",
        }
    }

    /// Calculate grade from a score (0-100)
    pub fn from_score(score: u32) -> Self {
        match score {
            98..=100 => Grade::APlus,
            93..=97 => Grade::A,
            90..=92 => Grade::AMinus,
            87..=89 => Grade::BPlus,
            83..=86 => Grade::B,
            80..=82 => Grade::BMinus,
            77..=79 => Grade::CPlus,
            73..=76 => Grade::C,
            70..=72 => Grade::CMinus,
            60..=69 => Grade::D,
            _ => Grade::F,
        }
    }
}

impl std::fmt::Display for Grade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Aggregated report card with all check results
#[derive(Debug, Clone, Serialize)]
pub struct ReportCard {
    /// Domain that was checked
    pub domain: String,
    /// Target IP address
    pub ip: String,
    /// Target port
    pub port: u16,
    /// Overall grade
    pub grade: Grade,
    /// Overall score (0-100)
    pub score: u32,
    /// DNS check results
    pub dns_result: Option<TestResult>,
    /// TCP check results
    pub tcp_result: Option<TestResult>,
    /// SSL/TLS check results
    pub ssl_result: Option<TestResult>,
    /// Certificate check results
    pub certificate_result: Option<TestResult>,
    /// WHOIS check results
    pub whois_result: Option<TestResult>,
    /// Timestamp of the check
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ReportCard {
    /// Create a new report card
    pub fn new(domain: String, ip: String, port: u16) -> Self {
        Self {
            domain,
            ip,
            port,
            grade: Grade::F,
            score: 0,
            dns_result: None,
            tcp_result: None,
            ssl_result: None,
            certificate_result: None,
            whois_result: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Calculate the overall grade based on individual results
    pub fn calculate_grade(&mut self) {
        let mut total_score = 0u32;
        let mut total_weight = 0u32;

        // Weight: DNS = 10, TCP = 10, SSL = 40, Cert = 40
        if let Some(ref result) = self.dns_result {
            total_score += self.status_to_score(result.status) * 10;
            total_weight += 10;
        }

        if let Some(ref result) = self.tcp_result {
            total_score += self.status_to_score(result.status) * 10;
            total_weight += 10;
        }

        if let Some(ref result) = self.ssl_result {
            total_score += self.status_to_score(result.status) * 40;
            total_weight += 40;
        }

        if let Some(ref result) = self.certificate_result {
            total_score += self.status_to_score(result.status) * 40;
            total_weight += 40;
        }

        if total_weight > 0 {
            self.score = total_score / total_weight;
        }

        self.grade = Grade::from_score(self.score);
    }

    fn status_to_score(&self, status: CheckStatus) -> u32 {
        match status {
            CheckStatus::Pass => 100,
            CheckStatus::Warning => 70,
            CheckStatus::Fail => 0,
        }
    }

    /// Get the overall status
    pub fn overall_status(&self) -> CheckStatus {
        let results = [
            &self.dns_result,
            &self.tcp_result,
            &self.ssl_result,
            &self.certificate_result,
        ];

        let has_fail = results
            .iter()
            .any(|r| r.as_ref().is_some_and(|r| r.status == CheckStatus::Fail));

        let has_warning = results
            .iter()
            .any(|r| r.as_ref().is_some_and(|r| r.status == CheckStatus::Warning));

        if has_fail {
            CheckStatus::Fail
        } else if has_warning {
            CheckStatus::Warning
        } else {
            CheckStatus::Pass
        }
    }

    /// Get all recommendations from all checks
    pub fn all_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        for r in [
            &self.dns_result,
            &self.tcp_result,
            &self.ssl_result,
            &self.certificate_result,
            &self.whois_result,
        ]
        .into_iter()
        .flatten()
        {
            recommendations.extend(r.recommendations.clone());
        }

        recommendations
    }
}
