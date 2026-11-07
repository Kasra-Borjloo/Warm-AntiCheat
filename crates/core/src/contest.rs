use crate::error::{Result, WarmError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents an authorized competition/contest specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contest {
    pub id: String,
    pub uuid: Uuid,
    pub title: String,
    pub organizer: String,
    pub description: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub retention_days: u32,
}

impl Contest {
    pub fn new(
        title: impl Into<String>,
        organizer: impl Into<String>,
        description: impl Into<String>,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Self> {
        let title = title.into().trim().to_string();
        let organizer = organizer.into().trim().to_string();
        let description = description.into().trim().to_string();

        if title.is_empty() {
            return Err(WarmError::Contest("Contest title cannot be empty".into()));
        }
        if organizer.is_empty() {
            return Err(WarmError::Contest("Organizer name cannot be empty".into()));
        }
        if end_time <= start_time {
            return Err(WarmError::Contest(
                "End time must be strictly after start time".into(),
            ));
        }

        let slug = slugify(&title);
        let uuid = Uuid::new_v4();

        Ok(Self {
            id: slug,
            uuid,
            title,
            organizer,
            description,
            start_time,
            end_time,
            created_at: Utc::now(),
            retention_days: 30,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.title.trim().is_empty() {
            return Err(WarmError::Contest("Contest title cannot be empty".into()));
        }
        if self.organizer.trim().is_empty() {
            return Err(WarmError::Contest("Organizer name cannot be empty".into()));
        }
        if self.id.trim().is_empty() {
            return Err(WarmError::Contest(
                "Contest identifier cannot be empty".into(),
            ));
        }
        if self.end_time <= self.start_time {
            return Err(WarmError::Contest(
                "End time must be strictly after start time".into(),
            ));
        }
        Ok(())
    }

    pub fn is_active_at(&self, time: DateTime<Utc>) -> bool {
        time >= self.start_time && time <= self.end_time
    }
}

/// Convert arbitrary contest title to URL- and file-safe identifier slug.
pub fn slugify(title: &str) -> String {
    let mut slug = String::new();
    let mut prev_dash = false;

    for ch in title.chars() {
        if ch.is_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            slug.push('-');
            prev_dash = true;
        }
    }

    let trimmed = slug.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "contest".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("GOCUP 1"), "gocup-1");
        assert_eq!(slugify("ACM-ICPC Regional 2026!"), "acm-icpc-regional-2026");
        assert_eq!(slugify("   "), "contest");
    }

    #[test]
    fn test_contest_creation_valid() {
        let start = Utc::now();
        let end = start + Duration::hours(5);
        let contest = Contest::new("GOCUP 1", "Sharif Org", "Annual contest", start, end).unwrap();

        assert_eq!(contest.title, "GOCUP 1");
        assert_eq!(contest.id, "gocup-1");
        assert!(contest.is_active_at(start + Duration::hours(2)));
        assert!(!contest.is_active_at(start - Duration::hours(1)));
        assert!(!contest.is_active_at(end + Duration::hours(1)));
    }

    #[test]
    fn test_contest_invalid_times() {
        let start = Utc::now();
        let end = start - Duration::hours(1);
        let res = Contest::new("GOCUP 1", "Org", "Desc", start, end);
        assert!(res.is_err());
    }
}
