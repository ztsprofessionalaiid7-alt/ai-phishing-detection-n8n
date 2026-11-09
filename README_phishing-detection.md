# AI Phishing Detection & Auto-Quarantine (n8n)

An n8n workflow that scans incoming emails, checks links with VirusTotal, asks Gemini to judge the risk, then alerts Slack, sends a warning email and logs every result to Postgres.

▶ **Demo video:** https://drive.google.com/file/d/1u-BVskM3UWhZB4ndbqgjNZKzp2ZwDzr6/view

## How it works

1. Mock emails are normalised and URLs are extracted
2. Emails with a link are sent to VirusTotal (submit, wait 15s, fetch result)
3. Gemini analyses sender, subject, body and the VirusTotal summary, and returns structured JSON (risk level and reason)
4. A Switch node routes by risk level to Slack alert, warning email and database log
5. Every email is saved to Supabase Postgres

```
Manual Trigger -> Mock Emails -> Normalize Email -> Has URL?
   yes -> VT Submit URL -> Wait 15s -> VT Get Result -> Prep Context
   no  ------------------------------------------------> Prep Context
Prep Context -> Analyze Email (Gemini + Output Parser) -> Parse AI JSON -> Switch
Switch -> Slack Alert -> Send Warning Email
Switch -> Log to Postgres
```

## Tech stack

n8n Cloud, Google Gemini, VirusTotal API, Slack, Supabase (Postgres), SMTP

## Setup

1. Import `phishing-detection-cloud.json` into n8n
2. Create credentials (all have free tiers):
   - Google Gemini (API key)
   - VirusTotal (Header Auth: name `x-apikey`, value your key)
   - Slack (Bot token and signing secret)
   - Postgres (Supabase Session pooler, SSL: Require)
   - SMTP (optional, for the warning email)
3. In the Slack Alert node set channel `phishing-alerts`, then run `/invite @your-bot` in that channel
4. Create the database table (below)
5. Click **Execute workflow**: 3 mock emails run through all branches

## Database

```sql
create table if not exists public.phishing_logs (
  id bigint generated always as identity primary key,
  sender text,
  subject text,
  risk_level text,
  reason text,
  created_at timestamptz default now()
);
```

## Demo data

| Mock email | Expected result |
|---|---|
| Fake PayPal support with link | High risk, VirusTotal checked |
| CEO gift card request | High risk (social engineering) |
| GitHub newsletter | Safe |

## Notes

- Never commit API keys. Use n8n credentials only
- In the Slack node the message text must be in **Expression** mode so `{{ }}` values are filled in

## Author

Zarin Tasnim Shaily, AI Automation Engineer
[LinkedIn](https://linkedin.com/in/5ha1l72) | [GitHub](https://github.com/ztsprofessionalaiid7-alt)
