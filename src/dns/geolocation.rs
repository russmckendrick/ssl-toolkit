//! IP geolocation functionality

use crate::error::{Result, SslToolkitError};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Geolocation information for an IP address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub ip: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
}

impl Default for GeoLocation {
    fn default() -> Self {
        GeoLocation {
            ip: String::new(),
            country: None,
            country_code: None,
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            timezone: None,
            isp: None,
            org: None,
            asn: None,
        }
    }
}

impl std::fmt::Display for GeoLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();

        if let Some(city) = &self.city {
            parts.push(city.clone());
        }
        if let Some(region) = &self.region {
            parts.push(region.clone());
        }
        if let Some(country) = &self.country {
            parts.push(country.clone());
        }

        if parts.is_empty() {
            write!(f, "{}", self.ip)
        } else {
            write!(f, "{} ({})", self.ip, parts.join(", "))
        }
    }
}

/// Response from ip-api.com
#[derive(Debug, Deserialize)]
struct IpApiResponse {
    status: String,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    region: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    asn: Option<String>,
}

/// Get geolocation information for an IP address
pub async fn get_geolocation(ip: &str) -> Result<GeoLocation> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| SslToolkitError::Http(e))?;

    // Using ip-api.com (free, no API key required for non-commercial use)
    let url = format!("http://ip-api.com/json/{}", ip);

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| SslToolkitError::Http(e))?;

    if !response.status().is_success() {
        return Ok(GeoLocation {
            ip: ip.to_string(),
            ..Default::default()
        });
    }

    let api_response: IpApiResponse = response
        .json()
        .await
        .map_err(|e| SslToolkitError::Http(e))?;

    if api_response.status != "success" {
        return Ok(GeoLocation {
            ip: ip.to_string(),
            ..Default::default()
        });
    }

    Ok(GeoLocation {
        ip: ip.to_string(),
        country: api_response.country,
        country_code: api_response.country_code,
        region: api_response.region_name.or(api_response.region),
        city: api_response.city,
        latitude: api_response.lat,
        longitude: api_response.lon,
        timezone: api_response.timezone,
        isp: api_response.isp,
        org: api_response.org,
        asn: api_response.asn,
    })
}

/// Get geolocation for multiple IP addresses
pub async fn get_geolocations(ips: &[String]) -> Vec<GeoLocation> {
    let mut locations = Vec::new();

    for ip in ips {
        match get_geolocation(ip).await {
            Ok(loc) => locations.push(loc),
            Err(_) => locations.push(GeoLocation {
                ip: ip.clone(),
                ..Default::default()
            }),
        }
    }

    locations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geolocation_display() {
        let geo = GeoLocation {
            ip: "8.8.8.8".to_string(),
            country: Some("United States".to_string()),
            city: Some("Mountain View".to_string()),
            region: Some("California".to_string()),
            ..Default::default()
        };

        let display = format!("{}", geo);
        assert!(display.contains("8.8.8.8"));
        assert!(display.contains("Mountain View"));
        assert!(display.contains("California"));
        assert!(display.contains("United States"));
    }

    #[test]
    fn test_geolocation_display_minimal() {
        let geo = GeoLocation {
            ip: "8.8.8.8".to_string(),
            ..Default::default()
        };

        let display = format!("{}", geo);
        assert_eq!(display, "8.8.8.8");
    }
}
