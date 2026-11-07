use chrono::Utc;
use uuid::Uuid;
use warm_core::{AccountRecord, AccountVerifier, Result, WarmError};
use warm_crypto::{generate_secure_password, hash_password};

pub fn generate_participant_accounts(
    contest_id: &str,
    count: usize,
) -> Result<(Vec<AccountRecord>, Vec<AccountVerifier>)> {
    if count == 0 || count > 10000 {
        return Err(WarmError::Validation(format!(
            "Account count must be between 1 and 10000, got {count}"
        )));
    }

    let slug_upper = contest_id.replace('_', "-").trim().to_ascii_uppercase();

    let mut records = Vec::with_capacity(count);
    let mut verifiers = Vec::with_capacity(count);

    for idx in 1..=count {
        let account_id = Uuid::new_v4();
        let username = format!("{slug_upper}-{idx:03}");
        let plaintext_password = generate_secure_password();
        let password_hash = hash_password(&plaintext_password)
            .map_err(|e| WarmError::Crypto(format!("Failed to hash password: {e}")))?;

        records.push(AccountRecord {
            account_id,
            username: username.clone(),
            plaintext_password,
            contest_id: contest_id.to_string(),
            created_at: Utc::now(),
        });

        verifiers.push(AccountVerifier {
            account_id,
            username,
            password_hash,
        });
    }

    Ok((records, verifiers))
}

pub fn export_credentials_csv(
    contest_name: &str,
    contest_id: &str,
    accounts: &[AccountRecord],
) -> String {
    let mut out =
        String::from("Contest Name,Contest ID,Participant Username,Password,Account UUID\n");
    for acc in accounts {
        let clean_name = contest_name.replace(',', " ");
        out.push_str(&format!(
            "\"{}\",{},{},{},{}\n",
            clean_name, contest_id, acc.username, acc.plaintext_password, acc.account_id
        ));
    }
    out
}

pub fn export_credentials_printable_html(
    contest_name: &str,
    contest_id: &str,
    accounts: &[AccountRecord],
) -> String {
    let mut out = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Credentials - {contest_name}</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; color: #1e293b; }}
    .header {{ margin-bottom: 2rem; border-bottom: 2px solid #0f172a; padding-bottom: 1rem; }}
    .cards-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; }}
    .card {{ border: 1px dashed #64748b; border-radius: 6px; padding: 1rem; page-break-inside: avoid; background: #f8fafc; }}
    .card h3 {{ margin: 0 0 0.5rem 0; font-size: 1.1rem; color: #0284c7; }}
    .row {{ display: flex; justify-content: space-between; margin: 0.25rem 0; font-size: 0.9rem; }}
    .pwd {{ font-family: monospace; font-weight: bold; background: #e2e8f0; padding: 0.15rem 0.4rem; border-radius: 4px; }}
    @media print {{ body {{ margin: 0.5cm; }} .card {{ border: 1px solid #000; }} }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Contest Credentials: {contest_name}</h1>
    <p>Contest ID: <code>{contest_id}</code> | Total Accounts: {count}</p>
  </div>
  <div class="cards-grid">
"#,
        contest_name = contest_name,
        contest_id = contest_id,
        count = accounts.len()
    );

    for acc in accounts {
        out.push_str(&format!(
            r#"    <div class="card">
      <h3>{username}</h3>
      <div class="row"><span>Password:</span> <span class="pwd">{pwd}</span></div>
      <div class="row"><small>UUID: {uuid}</small></div>
    </div>
"#,
            username = acc.username,
            pwd = acc.plaintext_password,
            uuid = acc.account_id
        ));
    }

    out.push_str("  </div>\n</body>\n</html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_participant_accounts_valid() {
        let (records, verifiers) = generate_participant_accounts("gocup-1", 10).unwrap();
        assert_eq!(records.len(), 10);
        assert_eq!(verifiers.len(), 10);

        for (idx, (rec, ver)) in records.iter().zip(verifiers.iter()).enumerate() {
            assert_eq!(rec.account_id, ver.account_id);
            assert_eq!(rec.username, ver.username);
            assert_eq!(rec.username, format!("GOCUP-1-{:03}", idx + 1));
            assert_eq!(rec.plaintext_password.len(), 8);
            assert!(warm_crypto::verify_password(
                &rec.plaintext_password,
                &ver.password_hash
            ));
        }
    }

    #[test]
    fn test_generate_participant_accounts_bounds() {
        assert!(generate_participant_accounts("gocup", 0).is_err());
        assert!(generate_participant_accounts("gocup", 10001).is_err());
    }

    #[test]
    fn test_export_credentials_csv() {
        let (records, _) = generate_participant_accounts("gocup", 2).unwrap();
        let csv = export_credentials_csv("GOCUP 2026", "gocup", &records);
        assert!(csv.contains("Contest Name,Contest ID,Participant Username,Password,Account UUID"));
        assert!(csv.contains("GOCUP-001"));
        assert!(csv.contains("GOCUP-002"));
    }
}
