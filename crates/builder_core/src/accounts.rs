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
    let mut out = String::from(
        "\u{FEFF}Contest Name,Contest ID,Participant Username,Password,Account UUID\n",
    );
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

fn escape_pdf(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

pub fn export_credentials_pdf(
    contest_name: &str,
    contest_id: &str,
    accounts: &[AccountRecord],
) -> Vec<u8> {
    let rows_per_page = 28;
    let total_pages = if accounts.is_empty() {
        1
    } else {
        accounts.len().div_ceil(rows_per_page)
    };

    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets = Vec::new();
    let num_fonts = 4;
    let page_tree_obj = 2;
    let font_start_obj = 3;
    let first_page_obj = font_start_obj + num_fonts;
    let total_objs = first_page_obj - 1 + total_pages * 2;

    offsets.push(pdf.len());
    pdf.extend_from_slice(
        format!("1 0 obj\n<< /Type /Catalog /Pages {page_tree_obj} 0 R >>\nendobj\n").as_bytes(),
    );

    let mut kids = String::new();
    for p in 0..total_pages {
        let p_obj = first_page_obj + p * 2;
        kids.push_str(&format!("{p_obj} 0 R "));
    }
    offsets.push(pdf.len());
    pdf.extend_from_slice(format!("{page_tree_obj} 0 obj\n<< /Type /Pages /Kids [ {kids}] /Count {total_pages} >>\nendobj\n").as_bytes());

    offsets.push(pdf.len());
    pdf.extend_from_slice(
        b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    );

    offsets.push(pdf.len());
    pdf.extend_from_slice(
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n",
    );

    offsets.push(pdf.len());
    pdf.extend_from_slice(
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >>\nendobj\n",
    );

    offsets.push(pdf.len());
    pdf.extend_from_slice(
        b"6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n",
    );

    let clean_title = escape_pdf(contest_name);
    let clean_id = escape_pdf(contest_id);

    for p in 0..total_pages {
        let page_obj_id = first_page_obj + p * 2;
        let content_obj_id = page_obj_id + 1;

        let start_idx = p * rows_per_page;
        let end_idx = (start_idx + rows_per_page).min(accounts.len());
        let page_accounts = if start_idx < accounts.len() {
            &accounts[start_idx..end_idx]
        } else {
            &[]
        };

        let mut stream = String::new();

        stream.push_str("0.05 0.25 0.5 rg\n");
        stream.push_str("BT /F2 16 Tf 40 805 Td (WARM-ANTICHEAT PARTICIPANT CREDENTIALS) Tj ET\n");

        stream.push_str("0.3 0.35 0.4 rg\n");
        stream.push_str(&format!(
            "BT /F1 10 Tf 40 788 Td (Contest: {} | ID: {} | Page {} of {}) Tj ET\n",
            clean_title,
            clean_id,
            p + 1,
            total_pages
        ));

        stream.push_str("0.85 0.15 0.15 rg\n");
        stream.push_str("40 762 515 16 re f\n");
        stream.push_str("1 1 1 rg\n");
        stream.push_str("BT /F2 8 Tf 45 767 Td (CONFIDENTIAL CREDENTIAL SHEET - CONTAINS PLAINTEXT PARTICIPANT PASSWORDS. KEEP SECURE.) Tj ET\n");

        stream.push_str("0.1 0.15 0.2 rg\n");
        stream.push_str("40 735 515 18 re f\n");
        stream.push_str("1 1 1 rg\n");
        stream.push_str("BT /F2 9 Tf 46 740 Td (#) Tj ET\n");
        stream.push_str("BT /F2 9 Tf 75 740 Td (PARTICIPANT USERNAME) Tj ET\n");
        stream.push_str("BT /F2 9 Tf 210 740 Td (PASSWORD) Tj ET\n");
        stream.push_str("BT /F2 9 Tf 300 740 Td (ACCOUNT IDENTIFIER UUID) Tj ET\n");

        let mut row_y = 717.0;
        for (i, acc) in page_accounts.iter().enumerate() {
            let row_idx = start_idx + i + 1;
            if i % 2 == 1 {
                stream.push_str(&format!("0.96 0.97 0.98 rg\n40 {row_y} 515 18 re f\n"));
            }

            stream.push_str(&format!(
                "0.88 0.88 0.88 RG\n0.5 w\n40 {row_y} 515 18 re S\n"
            ));

            stream.push_str("0.1 0.1 0.1 rg\n");
            stream.push_str(&format!(
                "BT /F1 8 Tf 46 {} Td ({}) Tj ET\n",
                row_y + 5.0,
                row_idx
            ));
            stream.push_str(&format!(
                "BT /F2 9 Tf 75 {} Td ({}) Tj ET\n",
                row_y + 5.0,
                escape_pdf(&acc.username)
            ));

            stream.push_str("0.02 0.4 0.2 rg\n");
            stream.push_str(&format!(
                "BT /F3 9 Tf 210 {} Td ({}) Tj ET\n",
                row_y + 5.0,
                escape_pdf(&acc.plaintext_password)
            ));

            stream.push_str("0.25 0.25 0.25 rg\n");
            stream.push_str(&format!(
                "BT /F4 8 Tf 300 {} Td ({}) Tj ET\n",
                row_y + 5.0,
                acc.account_id
            ));

            row_y -= 18.0;
        }

        stream.push_str("0.5 0.5 0.5 rg\n");
        stream.push_str(&format!(
            "BT /F1 8 Tf 40 30 Td (Warm-AntiCheat Offline Contest Integrity Framework | Generated: {} UTC) Tj ET\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S")
        ));

        let stream_bytes = stream.into_bytes();
        let stream_len = stream_bytes.len();

        offsets.push(pdf.len());
        pdf.extend_from_slice(format!(
            "{page_obj_id} 0 obj\n<< /Type /Page /Parent {page_tree_obj} 0 R /MediaBox [0 0 595.28 841.89] /Contents {content_obj_id} 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >> >> >>\nendobj\n"
        ).as_bytes());

        offsets.push(pdf.len());
        pdf.extend_from_slice(
            format!("{content_obj_id} 0 obj\n<< /Length {stream_len} >>\nstream\n").as_bytes(),
        );
        pdf.extend_from_slice(&stream_bytes);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
    }

    let xref_offset = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", total_objs + 1).as_bytes());
    for off in offsets {
        pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }

    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            total_objs + 1
        )
        .as_bytes(),
    );

    pdf
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
        assert!(csv.starts_with('\u{FEFF}'));
        assert!(csv.contains("Contest Name,Contest ID,Participant Username,Password,Account UUID"));
        assert!(csv.contains("GOCUP-001"));
        assert!(csv.contains("GOCUP-002"));
    }

    #[test]
    fn test_export_credentials_pdf() {
        let (records, _) = generate_participant_accounts("gocup", 5).unwrap();
        let pdf = export_credentials_pdf("GOCUP 2026", "gocup", &records);
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n") || pdf.ends_with(b"%%EOF"));
        let pdf_str = String::from_utf8_lossy(&pdf);
        assert!(pdf_str.contains("/Type /Catalog"));
        assert!(pdf_str.contains("/Type /Page"));
        assert!(pdf_str.contains("CONFIDENTIAL"));
        assert!(pdf_str.contains("GOCUP-001"));
    }
}
