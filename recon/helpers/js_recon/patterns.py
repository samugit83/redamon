"""
JS Recon Secret Detection Patterns

240+ hardcoded regex patterns for detecting secrets, credentials, tokens,
infrastructure URLs, and sensitive information in JavaScript files.

Covers all major cloud providers, AI/LLM services, payment processors,
observability tools, CI/CD systems, and SaaS platforms. Superset of
github_secret_hunt SECRET_PATTERNS with JS-specific additions and validators.
"""

import re
import json
import math
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional


def _token(prefix: str, rest: str) -> str:
    """A vendor token: the literal `prefix`, then `rest`, never inside a longer
    identifier. `foosk_live_...` or `xghp_...` is the tail of another string,
    not a key the vendor issued, so a letter or digit right before the prefix
    blocks the match. Anything else is a boundary: `_`, quotes, `=`, `/`, and
    an escape ending in a letter or digit (`\\n`, `%22`, `\\x22`, `\\u0022`),
    so a key inside an encoded string still fires.

    The check sits after the literal, in lookbehinds that repeat it: a
    lookbehind in front of the literal hides it from `re`'s literal search and
    made each rule about 100 times slower on a large bundle."""
    p = re.escape(prefix)
    return (p + rf"(?:(?<![A-Za-z0-9]{p})|(?<=\\[nrtvfb0]{p})|(?<=%[0-9A-Fa-f]{{2}}{p})"
            rf"|(?<=\\x[0-9A-Fa-f]{{2}}{p})|(?<=\\u[0-9A-Fa-f]{{4}}{p}))" + rest)


# Each pattern: name, regex (raw string), severity, confidence, category, validator_ref (optional).
# A rule that starts with a vendor's literal prefix is written _token(prefix, rest).
_RAW_PATTERNS = [
    # Confidence `high` is for a value with a provider-specific shape (AKIA, ghp_,
    # xoxb-, sk_live_ ...). A generic run found only by a keyword nearby is
    # `medium`: the Priority Board reads high as C 0.75, enough for "Act soon"
    # before anything validated it.
    # ========== CLOUD CREDENTIALS (Critical) ==========
    ("AWS Access Key ID", _token("AKIA", r"[0-9A-Z]{16}"), "critical", "high", "cloud", "validate_aws"),
    ("AWS Secret Key", r"(?i)aws(?:_secret|_key|secret_key|_access).{0,10}['\"][0-9a-zA-Z/+]{40}['\"]", "critical", "medium", "cloud", "validate_aws"),
    # Temporary STS credentials: the ID alone cannot sign a request, so high,
    # and medium confidence (an `ASIA` + 16 run also occurs in random text).
    ("AWS Session Key", _token("ASIA", r"[0-9A-Z]{16}"), "high", "medium", "cloud", None),
    ("AWS MWS Key", _token("amzn.mws.", r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "critical", "high", "cloud", None),
    ("GCP API Key", _token("AIza", r"[0-9A-Za-z\-_]{35}"), "critical", "high", "cloud", "validate_google_maps"),
    ("GCP OAuth Client", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "high", "high", "cloud", None),
    ("GCP Service Account", r"\"type\":\s*\"service_account\"", "critical", "high", "cloud", None),
    ("Google OAuth Token", _token("ya29.", r"[0-9A-Za-z\-_]+"), "high", "high", "cloud", None),
    ("Google reCAPTCHA Key", _token("6L", r"[0-9A-Za-z-_]{38}"), "low", "medium", "cloud", None),
    ("Firebase URL", r"https://[a-z0-9-]+\.firebaseio\.com", "high", "high", "cloud", "validate_firebase"),
    ("Firebase API Key", r"(?i)firebase[^\"']{0,50}['\"][A-Za-z0-9_]{30,}['\"]", "high", "medium", "cloud", None),
    ("Firebase Storage", r"https://[a-z0-9-]+\.firebasestorage\.app", "medium", "high", "cloud", None),
    ("Azure Storage Key", r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "critical", "high", "cloud", None),
    ("Azure Connection String", r"(?i)(AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{40,}", "critical", "medium", "cloud", None),
    ("Azure SAS Token", r"(?i)[?&]sig=[A-Za-z0-9%]{40,}", "high", "medium", "cloud", None),
    # A presigned S3 URL (SigV4: the signature and the credential it was made
    # with) or a GCS V4 signed URL: whoever holds it reads or writes the object
    # until it expires. Low once X-*-Date + X-*-Expires has passed (_refine).
    ("Signed URL in client code", r"https?://[^\s'\"<>\\]{1,1024}?\?(?:(?=[^\s'\"<>\\]{0,1024}?X-Amz-Credential=)[^\s'\"<>\\]{0,1024}?X-Amz-Signature=[0-9a-fA-F]{64}|[^\s'\"<>\\]{0,1024}?X-Goog-Signature=[0-9a-fA-F]{64,})[^\s'\"<>\\]{0,1024}", "medium", "high", "cloud", None),
    # The value must be ASSIGNED to the client-secret key, near an Azure keyword:
    # "azure" anywhere plus any long quoted string later used to be enough.
    # Medium: the value itself has no provider prefix.
    ("Azure AD Client Secret", r"(?i)(?:azure|msal|aad)[^\n]{0,120}?client.?secret[\"']?\s*[:=]\s*[\"'][a-zA-Z0-9~._-]{34,}[\"']", "critical", "medium", "cloud", None),
    ("DigitalOcean Token", _token("dop_v1_", r"[a-f0-9]{64}"), "critical", "high", "cloud", "validate_digitalocean"),
    ("DigitalOcean OAuth", _token("doo_v1_", r"[a-f0-9]{64}"), "critical", "high", "cloud", None),
    ("DigitalOcean Refresh Token", _token("dor_v1_", r"[a-f0-9]{64}"), "critical", "high", "cloud", None),
    ("Cloudflare API Key", r"(?i)cloudflare[^\n]{0,120}?['\"][a-z0-9]{37}['\"]", "high", "medium", "cloud", "validate_cloudflare"),
    ("Cloudflare API Token", r"(?i)cloudflare[^\n]{0,120}?['\"][A-Za-z0-9_-]{40}['\"]", "high", "medium", "cloud", "validate_cloudflare"),
    ("Cloudflare Origin CA Key", _token("v1.0-", r"[a-f0-9]{24}-[a-f0-9]{146}"), "high", "high", "cloud", None),
    ("Cloudflare Global API Key", r"(?i)cloudflare[^\n]{0,120}?global[^\n]{0,120}?['\"][a-f0-9]{37}['\"]", "high", "medium", "cloud", None),
    ("Alibaba Access Key ID", r"\bLTAI[a-zA-Z0-9]{20}\b", "critical", "high", "cloud", None),
    ("Alibaba Secret Key", r"(?i)alibaba[^\n]{0,120}?['\"][a-z0-9]{30}['\"]", "high", "medium", "cloud", None),
    ("Yandex API Key", r"(?i)yandex[^\n]{0,120}?['\"]AQVN[a-zA-Z0-9_\-]{35,38}['\"]", "high", "medium", "cloud", None),
    ("Yandex AWS Access Token", _token("YC", r"[a-zA-Z0-9_\-]{38}"), "high", "medium", "cloud", None),

    # ========== PAYMENT / FINANCIAL (Critical) ==========
    ("Stripe Secret Key", _token("sk_live_", r"[0-9a-zA-Z]{24,}"), "critical", "high", "payment", "validate_stripe"),
    ("Stripe Test Key", _token("sk_test_", r"[0-9a-zA-Z]{24,}"), "medium", "high", "payment", None),
    ("Stripe Restricted Key", _token("rk_live_", r"[0-9a-zA-Z]{24,}"), "critical", "high", "payment", None),
    ("Stripe Publishable Key", _token("pk_live_", r"[0-9a-zA-Z]{24,}"), "low", "high", "payment", None),
    # Signs webhook payloads: whoever holds it forges Stripe events to the app.
    ("Stripe Webhook Secret", _token("whsec_", r"[A-Za-z0-9]{32,}"), "high", "high", "payment", None),
    ("PayPal Client ID", r"(?i)paypal[^\n]{0,120}?client[_-]?id[^\n]{0,120}?['\"][A-Za-z0-9-]{20,}['\"]", "high", "medium", "payment", None),
    ("PayPal Braintree Token", _token("access_token$production$", r"[0-9a-z]{16}\$[0-9a-f]{32}"), "critical", "high", "payment", None),
    ("Square Access Token", _token("sq0atp-", r"[0-9A-Za-z\-_]{22}"), "critical", "high", "payment", None),
    ("Square OAuth Secret", _token("sq0csp-", r"[0-9A-Za-z\-_]{43}"), "critical", "high", "payment", None),
    ("Razorpay Key", _token("rzp_", r"(live|test)_[a-zA-Z0-9]{14}"), "high", "high", "payment", None),
    ("Plaid Client ID", r"(?i)plaid[^\n]{0,120}?client.?id[^\n]{0,120}?['\"][a-f0-9]{24}['\"]", "high", "medium", "payment", None),
    ("Plaid Secret Key", r"(?i)plaid[^\n]{0,120}?secret[^\n]{0,120}?['\"][a-f0-9]{30}['\"]", "critical", "medium", "payment", None),
    ("Flutterwave Secret Key", _token("FLWSECK-", r"[a-zA-Z0-9]{32}-X"), "critical", "high", "payment", None),
    ("Flutterwave Public Key", _token("FLWPUBK-", r"[a-zA-Z0-9]{32}-X"), "medium", "high", "payment", None),
    ("GoCardless API Token", r"(?i)gocardless[^\n]{0,120}?['\"]live_[a-zA-Z0-9\-_]{40,}['\"]", "critical", "medium", "payment", None),
    ("Coinbase Access Token", r"(?i)coinbase[^\n]{0,120}?['\"][a-zA-Z0-9]{64}['\"]", "high", "medium", "payment", None),

    # ========== AI / LLM PROVIDERS (Critical) ==========
    ("OpenAI API Key", _token("sk-", r"[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"), "critical", "high", "ai_llm", "validate_openai"),
    ("OpenAI Project Key", _token("sk-proj-", r"[a-zA-Z0-9_-]{80,}"), "critical", "high", "ai_llm", "validate_openai"),
    ("Anthropic API Key", _token("sk-ant-api03-", r"[a-zA-Z0-9_\-]{93}AA"), "critical", "high", "ai_llm", None),
    ("Anthropic Admin Key", _token("sk-ant-admin01-", r"[a-zA-Z0-9_\-]{93}AA"), "critical", "high", "ai_llm", None),
    ("HuggingFace Access Token", _token("hf_", r"[a-zA-Z]{34}"), "high", "high", "ai_llm", None),
    ("HuggingFace Org Token", _token("api_org_", r"[a-zA-Z0-9]{34}"), "high", "high", "ai_llm", None),
    ("Cohere API Token", r"(?i)cohere[^\n]{0,120}?['\"][a-zA-Z0-9]{40}['\"]", "high", "medium", "ai_llm", None),
    ("Perplexity API Key", _token("pplx-", r"[a-f0-9]{48}"), "high", "high", "ai_llm", None),
    ("Replicate API Token", _token("r8_", r"[a-zA-Z0-9]{40}"), "high", "high", "ai_llm", None),
    ("Google Gemini API Key", r"(?i)gemini[^\n]{0,120}?['\"]AIza[0-9A-Za-z\-_]{35}['\"]", "critical", "high", "ai_llm", None),
    ("Mistral API Key", r"(?i)mistral[^\n]{0,120}?['\"][a-zA-Z0-9]{32}['\"]", "high", "medium", "ai_llm", None),
    ("Groq API Key", _token("gsk_", r"[a-zA-Z0-9]{52}"), "high", "high", "ai_llm", None),
    ("Together AI Key", r"(?i)together[^\n]{0,120}?['\"][a-f0-9]{64}['\"]", "high", "medium", "ai_llm", None),
    ("Deepseek API Key", r"(?i)deepseek[^\n]{0,120}?['\"]sk-[a-f0-9]{48}['\"]", "high", "medium", "ai_llm", None),

    # ========== AUTHENTICATION TOKENS (High) ==========
    ("GitHub Token Classic", _token("ghp_", r"[0-9a-zA-Z]{36}"), "high", "high", "auth", "validate_github"),
    ("GitHub Fine-grained Token", _token("github_pat_", r"[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}"), "high", "high", "auth", "validate_github"),
    ("GitHub OAuth Token", _token("gho_", r"[0-9a-zA-Z]{36}"), "high", "high", "auth", "validate_github"),
    ("GitHub App Token", _token("gh", r"[us]_[0-9a-zA-Z]{36}"), "high", "high", "auth", "validate_github"),
    ("GitHub Refresh Token", _token("ghr_", r"[0-9a-zA-Z]{36}"), "high", "high", "auth", None),
    ("GitHub Credentials URL", r"[a-zA-Z0-9_-]{0,64}:[a-zA-Z0-9_\-]{1,128}@github\.com", "high", "high", "auth", None),
    ("GitLab PAT", _token("glpat-", r"[0-9a-zA-Z\-_]{20}"), "high", "high", "auth", "validate_gitlab"),
    ("GitLab Runner Token", _token("GR1348941", r"[0-9a-zA-Z\-_]{20}"), "high", "high", "auth", None),
    ("GitLab Pipeline Token", _token("glptt-", r"[0-9a-zA-Z\-_]{20}"), "high", "high", "auth", None),
    ("GitLab Deploy Token", _token("gldt-", r"[0-9a-zA-Z\-_]{20}"), "high", "high", "auth", None),
    ("GitLab CICD Job Token", _token("glcbt-", r"[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}"), "high", "high", "auth", None),
    ("GitLab Feed Token", _token("glft-", r"[0-9a-zA-Z\-_]{20}"), "high", "high", "auth", None),
    ("GitLab SCIM Token", _token("glsoat-", r"[0-9a-zA-Z\-_]{20}"), "high", "high", "auth", None),
    ("GitLab OAuth App Secret", _token("gloas-", r"[0-9a-f]{64}"), "high", "high", "auth", None),
    ("Slack Bot Token", _token("xoxb-", r"[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"), "high", "high", "auth", "validate_slack"),
    ("Slack User Token", _token("xoxp-", r"[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"), "high", "high", "auth", "validate_slack"),
    ("Slack App Token", _token("xapp-", r"[0-9]{1,2}-[A-Z0-9]+-[0-9]+-[a-z0-9]+"), "high", "high", "auth", None),
    ("Slack Legacy Token", _token("xox", r"[os]-[0-9]{10,13}-[a-zA-Z0-9]{10,48}"), "high", "high", "auth", None),
    ("Slack Config Token", _token("xoxe.xox", r"[bp]-[0-9]-[a-zA-Z0-9]{160,}"), "high", "high", "auth", None),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "high", "high", "auth", None),
    ("Discord Bot Token", r"[MN][A-Za-z\d]{23,}\.[\w-]{4,7}\.[\w-]{27,}", "high", "high", "auth", "validate_discord"),
    ("Discord Webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "high", "high", "auth", None),
    # Automation webhooks: a POST runs the owner's scenario, as Slack/Discord ones post.
    ("Zapier Webhook", r"https://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+/?", "high", "high", "auth", None),
    ("Make Webhook", r"https://hook\.[a-z0-9]+\.make\.com/[A-Za-z0-9]+", "high", "high", "auth", None),
    ("Twilio API Key", r"\bSK[0-9a-fA-F]{32}\b", "high", "high", "auth", "validate_twilio"),
    ("Twilio Account SID", r"\bAC[a-zA-Z0-9]{32}\b", "medium", "high", "auth", "validate_twilio_format"),
    ("Twilio App SID", r"\bAP[a-zA-Z0-9_\-]{32}\b", "medium", "high", "auth", None),
    ("SendGrid API Key", _token("SG.", r"[a-zA-Z0-9]{22}\.[a-zA-Z0-9\-_]{43}"), "high", "high", "auth", "validate_sendgrid"),
    # Not inside `pubkey-...`, the public key below.
    ("Mailgun API Key", r"(?<![A-Za-z0-9])key-[0-9a-zA-Z]{32}", "high", "high", "auth", "validate_mailgun"),
    ("Mailgun Public Key", _token("pubkey-", r"[a-f0-9]{32}"), "medium", "high", "auth", None),
    ("Mailchimp API Key", r"[0-9a-f]{32}-us[0-9]{1,2}", "high", "high", "auth", "validate_mailchimp"),
    ("SendinBlue API Key", _token("xkeysib-", r"[a-f0-9]{64}-[a-zA-Z0-9]{16}"), "high", "high", "auth", None),
    ("Telegram Bot Token", r"[0-9]+:AA[0-9A-Za-z\-_]{33}", "high", "high", "auth", "validate_telegram"),
    ("Postmark Server Token", r"(?i)postmark[^\n]{0,120}?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "high", "medium", "auth", "validate_postmark"),
    ("Okta API Token", r"(?i)okta[^\n]{0,120}?['\"][0-9a-zA-Z_-]{42}['\"]", "high", "medium", "auth", "validate_okta"),
    ("Auth0 Client Secret", r"(?i)auth0[^\n]{0,120}?client.?secret[^\n]{0,120}?['\"][a-zA-Z0-9_-]{32,}['\"]", "high", "medium", "auth", None),
    ("Heroku API Key", r"(?i)heroku[^\n]{0,120}?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "high", "medium", "auth", "validate_heroku"),
    ("HubSpot API Key", r"(?i)hubspot[^\n]{0,120}?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "high", "medium", "auth", "validate_hubspot"),
    ("Shopify Access Token", _token("shpat_", r"[a-fA-F0-9]{32}"), "high", "high", "auth", "validate_shopify"),
    ("Shopify Custom Access Token", _token("shpca_", r"[a-fA-F0-9]{32}"), "high", "high", "auth", None),
    ("Shopify Private App Token", _token("shppa_", r"[a-fA-F0-9]{32}"), "high", "high", "auth", None),
    ("Shopify Shared Secret", _token("shpss_", r"[a-fA-F0-9]{32}"), "high", "high", "auth", None),
    ("Twitter Bearer Token", r"(?<![A-Za-z0-9+/=])AAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{30,}(?![A-Za-z0-9+/=])", "high", "medium", "auth", "validate_twitter_format"),
    ("Twitter API Secret", r"(?i)twitter[^\n]{0,120}?api[_-]?secret[^\n]{0,120}?['\"][0-9a-zA-Z]{50}['\"]", "high", "medium", "auth", None),
    ("Facebook Access Token", _token("EAACEdEose0cBA", r"[0-9A-Za-z]+"), "high", "high", "auth", None),
    ("Facebook Page Token", _token("EAA", r"[MC][a-zA-Z0-9]{100,}"), "high", "high", "auth", None),
    ("Facebook Secret", r"(?i)facebook[^\n]{0,120}?(?:secret|app.?secret)[^\n]{0,120}?['\"][a-f0-9]{32}['\"]", "high", "medium", "auth", None),
    ("LinkedIn Client Secret", r"(?i)linkedin[^\n]{0,120}?client.?secret[^\n]{0,120}?['\"][a-zA-Z0-9]{16}['\"]", "high", "medium", "auth", None),
    ("Twitch API Token", r"(?i)twitch[^\n]{0,120}?['\"][a-z0-9]{30}['\"]", "high", "medium", "auth", None),
    ("Microsoft Teams Webhook", r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+", "high", "high", "auth", None),
    ("Mattermost Access Token", r"(?i)mattermost[^\n]{0,120}?['\"][a-z0-9]{26}['\"]", "high", "medium", "auth", None),
    ("MessageBird API Token", r"(?i)messagebird[^\n]{0,120}?['\"][a-zA-Z0-9]{25}['\"]", "high", "medium", "auth", None),
    ("Gitter Access Token", r"(?i)gitter[^\n]{0,120}?['\"][a-f0-9]{40}['\"]", "high", "medium", "auth", None),
    ("Intercom API Key", r"(?i)intercom[^\n]{0,120}?['\"][a-z0-9=_]{60}['\"]", "high", "medium", "auth", None),

    # ========== OBSERVABILITY & MONITORING ==========
    ("Sentry DSN", r"https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+", "medium", "high", "js_service", None),
    ("Sentry Access Token", _token("sntrys_", r"[a-zA-Z0-9]{56,}"), "high", "high", "js_service", None),
    ("Sentry Org Token", _token("sntryo_", r"[a-zA-Z0-9]{56,}"), "high", "high", "js_service", None),
    ("Datadog API Key", r"(?i)datadog[^\n]{0,120}?['\"][a-f0-9]{32}['\"]", "high", "medium", "js_service", None),
    ("Datadog App Key", r"(?i)datadog[^\n]{0,120}?app[^\n]{0,120}?key[^\n]{0,120}?['\"][a-f0-9]{40}['\"]", "high", "medium", "js_service", None),
    ("New Relic Insert Key", _token("NRII-", r"[A-Za-z0-9-_]{32}"), "high", "high", "js_service", None),
    ("New Relic User API Key", _token("NRAK-", r"[A-Z0-9]{27}"), "high", "high", "js_service", None),
    ("New Relic Browser API Token", _token("NRJS-", r"[a-f0-9]{19}"), "medium", "high", "js_service", None),
    ("Grafana API Key", _token("eyJrIjoi", r"[a-zA-Z0-9+/=]{60,}"), "high", "high", "js_service", None),
    ("Grafana Cloud Token", _token("glc_", r"[A-Za-z0-9+/]{32,}={0,2}"), "high", "high", "js_service", None),
    ("Grafana Service Account Token", _token("glsa_", r"[A-Za-z0-9]{32}_[a-f0-9]{8}"), "high", "high", "js_service", None),
    ("Dynatrace API Token", _token("dt0c01.", r"[A-Z0-9]{24}\.[A-Z0-9]{64}"), "high", "high", "js_service", None),
    ("SumoLogic Access ID", r"(?i)sumo[^\n]{0,120}?access.?id[^\n]{0,120}?['\"]su[a-zA-Z0-9]{12}['\"]", "high", "medium", "js_service", None),
    ("SumoLogic Access Token", r"(?i)sumo[^\n]{0,120}?access.?key[^\n]{0,120}?['\"][a-zA-Z0-9]{64}['\"]", "high", "medium", "js_service", None),

    # ========== JS-SPECIFIC SERVICES (High/Medium) ==========
    ("Algolia API Key", r"(?i)algolia[^\n]{0,120}?['\"][a-f0-9]{32}['\"]", "high", "medium", "js_service", None),
    ("Algolia App ID", r"(?i)algolia[^\n]{0,120}?app.?id[^\n]{0,120}?['\"][A-Z0-9]{10}['\"]", "low", "medium", "js_service", None),
    ("Mapbox Token", _token("pk.", r"[a-zA-Z0-9]{60,}"), "medium", "high", "js_service", None),
    ("Pusher Key", r"(?i)pusher[^\n]{0,120}?key[^\n]{0,120}?['\"][a-f0-9]{20}['\"]", "medium", "medium", "js_service", None),
    ("Pusher Secret", r"(?i)pusher[^\n]{0,120}?secret[^\n]{0,120}?['\"][a-f0-9]{40}['\"]", "high", "medium", "js_service", None),
    ("Intercom App ID", r"(?i)intercom[^\n]{0,120}?app.?id[^\n]{0,120}?['\"][a-z0-9]{8}['\"]", "low", "medium", "js_service", None),
    ("Segment Write Key", r"(?i)segment[^\n]{0,120}?write.?key[^\n]{0,120}?['\"][a-zA-Z0-9]{32}['\"]", "medium", "medium", "js_service", None),
    ("Amplitude API Key", r"(?i)amplitude[^\n]{0,120}?api.?key[^\n]{0,120}?['\"][a-f0-9]{32}['\"]", "medium", "medium", "js_service", None),
    ("LaunchDarkly SDK Key", "(?i)" + _token("sdk-", r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"), "medium", "high", "js_service", None),
    ("LaunchDarkly Access Token", "(?i)" + _token("api-", r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"), "high", "high", "js_service", None),
    ("Contentful Token", r"(?i)contentful[^\n]{0,120}?['\"][a-zA-Z0-9_-]{43}['\"]", "medium", "medium", "js_service", None),
    # A JWT: its `role` claim renames it "Supabase anon key" (public) or
    # "Supabase service_role key" (critical); see _refine.
    ("Supabase Key", r"(?i)supabase[^\n]{0,120}?(?:anon|service)[^\n]{0,120}?key[^\n]{0,120}?eyJ[A-Za-z0-9-_]+", "high", "medium", "js_service", None),
    ("Supabase Secret Key", r"\bsb_secret_[A-Za-z0-9_-]{20,}", "critical", "high", "js_service", None),
    ("Supabase Publishable Key", r"\bsb_publishable_[A-Za-z0-9_-]{20,}", "low", "high", "js_service", None),
    ("PlanetScale Token", _token("pscale_tkn_", r"[a-zA-Z0-9_-]{43}"), "high", "high", "js_service", None),
    ("PlanetScale OAuth Token", _token("pscale_otkn_", r"[a-zA-Z0-9_-]{43}"), "high", "high", "js_service", None),
    ("PlanetScale Password", _token("pscale_pw_", r"[a-zA-Z0-9_-]{43}"), "high", "high", "js_service", None),
    ("Vercel Token", r"(?i)vercel[^\n]{0,120}?['\"][a-zA-Z0-9]{24}['\"]", "high", "medium", "js_service", None),
    ("Next.js Env Leak", r"__NEXT_DATA__.{0,5000}(?:apiKey|secret|token|password)", "high", "medium", "js_service", None),
    ("Airtable API Key", r"(?i)airtable[^\n]{0,120}?['\"][a-z0-9]{17}['\"]", "high", "medium", "js_service", None),
    ("Airtable PAT", r"\bpat[a-zA-Z0-9]{14}\.[a-f0-9]{64}\b", "high", "high", "js_service", None),

    # ========== DEV TOOLS & PROJECT MANAGEMENT ==========
    ("Atlassian API Token", _token("ATATT3", r"[A-Za-z0-9_\-=]{186}"), "high", "high", "auth", None),
    ("Notion API Token", r"(?i)notion[^\n]{0,120}?secret_[a-zA-Z0-9]{43}", "high", "medium", "auth", None),
    ("Linear API Key", _token("lin_api_", r"[a-zA-Z0-9]{40}"), "high", "high", "auth", None),
    ("Linear Client Secret", r"(?i)linear[^\n]{0,120}?client.?secret[^\n]{0,120}?['\"][a-f0-9]{32}['\"]", "high", "medium", "auth", None),
    ("Asana Client ID", r"(?i)asana[^\n]{0,120}?['\"][0-9]{16}['\"]", "medium", "medium", "auth", None),
    ("Asana Client Secret", r"(?i)asana[^\n]{0,120}?secret[^\n]{0,120}?['\"][a-z0-9]{32}['\"]", "high", "medium", "auth", None),
    ("Postman API Token", _token("PMAK-", r"[a-f0-9]{24}-[a-f0-9]{34}"), "high", "high", "auth", None),
    ("Bitbucket Client ID", r"(?i)bitbucket[^\n]{0,120}?client.?id[^\n]{0,120}?['\"][a-zA-Z0-9]{32}['\"]", "medium", "medium", "auth", None),
    ("Bitbucket Client Secret", r"(?i)bitbucket[^\n]{0,120}?client.?secret[^\n]{0,120}?['\"][a-zA-Z0-9_\-]{64}['\"]", "high", "medium", "auth", None),
    ("Snyk API Token", r"(?i)snyk[^\n]{0,120}?['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]", "high", "medium", "auth", None),
    ("SonarQube Token", _token("sqa_", r"[a-zA-Z0-9]{40}"), "high", "high", "auth", None),
    ("Sourcegraph Access Token", _token("sgp_", r"[a-f0-9]{40}"), "high", "high", "auth", None),
    ("Codecov Access Token", r"codecov[^\n]{0,120}?['\"][a-f0-9]{32}['\"]", "high", "medium", "auth", None),

    # ========== CI/CD & INFRASTRUCTURE ==========
    ("HashiCorp Vault Service Token", r"\bhvs\.[a-zA-Z0-9_-]{24,}\b", "critical", "high", "secret", None),
    ("HashiCorp Vault Batch Token", r"\bhvb\.[a-zA-Z0-9_-]{24,}\b", "critical", "high", "secret", None),
    ("HashiCorp Terraform Token", r"(?i)terraform[^\n]{0,120}?['\"][a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,}['\"]", "critical", "high", "secret", None),
    ("Doppler API Token", _token("dp.pt.", r"[a-zA-Z0-9]{43}"), "high", "high", "secret", None),
    ("Pulumi Access Token", _token("pul-", r"[a-f0-9]{40}"), "high", "high", "secret", None),
    ("Infracost API Token", _token("ico-", r"[a-zA-Z0-9]{32}"), "high", "high", "secret", None),
    # Left boundary: `dapi` + 32 also sits inside base64 integrity hashes.
    ("Databricks API Token", r"(?<![A-Za-z0-9_])dapi[a-h0-9]{32}", "high", "high", "secret", None),
    ("Netlify Access Token", _token("nfp_", r"[a-zA-Z0-9]{40}"), "high", "high", "secret", None),
    ("Fly.io Access Token", _token("FlyV1", r"\s+fm1r_[a-zA-Z0-9_-]{43}"), "high", "high", "secret", None),
    ("Scalingo API Token", _token("tk-us-", r"[a-zA-Z0-9-_]{48}"), "high", "high", "secret", None),
    ("Render API Token", _token("rnd_", r"[a-zA-Z0-9]{32}"), "high", "high", "secret", None),
    ("Travis CI Token", r"(?i)travis[^\n]{0,120}?['\"][a-zA-Z0-9]{20,}['\"]", "high", "medium", "secret", None),
    ("CircleCI Token", r"(?i)circle[^\n]{0,120}?token[^\n]{0,120}?['\"][a-f0-9]{40}['\"]", "high", "medium", "secret", None),
    ("DroneCI Access Token", r"(?i)drone[^\n]{0,120}?['\"][a-zA-Z0-9]{32,}['\"]", "high", "medium", "secret", None),
    ("Octopus Deploy API Key", _token("API-", r"[A-Z0-9]{25}"), "high", "high", "secret", None),
    ("OpenShift User Token", _token("sha256~", r"[a-zA-Z0-9_-]{43}"), "high", "high", "secret", None),
    ("Harness API Key", r"(?i)harness[^\n]{0,120}?pat\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}", "high", "medium", "secret", None),

    # ========== MISC SAAS ==========
    ("Dropbox Short-lived Token", r"\bsl\.[A-Za-z0-9\-_]{130,}\b", "high", "high", "auth", None),
    ("Freshbooks Access Token", r"(?i)freshbooks[^\n]{0,120}?['\"][a-f0-9]{64}['\"]", "high", "medium", "auth", None),
    ("Zendesk Secret Key", r"(?i)zendesk[^\n]{0,120}?['\"][a-zA-Z0-9]{40}['\"]", "high", "medium", "auth", None),
    ("Typeform API Token", _token("tfp_", r"[a-zA-Z0-9_-]{40,}"), "high", "high", "auth", None),
    ("Beamer API Token", r"(?i)beamer[^\n]{0,120}?b_[a-zA-Z0-9=_-]{44}", "medium", "medium", "auth", None),
    ("ReadMe API Token", _token("rdme_", r"[a-z0-9]{70}"), "high", "high", "auth", None),
    ("Fastly API Token", r"(?i)fastly[^\n]{0,120}?['\"][a-zA-Z0-9_-]{32}['\"]", "high", "medium", "auth", None),
    ("Shippo API Token", _token("shippo_", r"(?:live|test)_[a-f0-9]{40}"), "high", "high", "auth", None),
    ("Duffel API Token", _token("duffel_", r"(?:live|test)_[a-zA-Z0-9_-]{43}"), "high", "high", "auth", None),
    ("EasyPost API Token", _token("EZAK", r"[a-f0-9]{54}"), "high", "high", "auth", None),
    ("Frame.io API Token", _token("fio-u-", r"[a-zA-Z0-9\-_=]{64}"), "high", "high", "auth", None),
    ("Adobe Client Secret", r"\bp8e-[a-zA-Z0-9]{32}\b", "high", "high", "auth", None),
    ("Etsy Access Token", r"(?i)etsy[^\n]{0,120}?['\"][a-z0-9]{24}['\"]", "high", "medium", "auth", None),
    ("Squarespace Access Token", r"(?i)squarespace[^\n]{0,120}?['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]", "high", "medium", "auth", None),

    # ========== PASSWORD MANAGERS ==========
    ("1Password Secret Key", r"\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b", "critical", "high", "secret", None),
    ("1Password Service Account Token", _token("ops_eyJ", r"[a-zA-Z0-9+/]{250,}={0,3}"), "critical", "high", "secret", None),

    # ========== SECURITY TOOLS ==========
    ("Age Secret Key", _token("AGE-SECRET-KEY-1", r"[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"), "critical", "high", "secret", None),
    ("JFrog API Key", r"\bAKCp[A-Za-z0-9]{69}\b", "high", "high", "secret", None),
    ("JFrog Reference Token", r"\bcmVmd[A-Za-z0-9]{59}\b", "high", "high", "secret", None),

    # ========== PACKAGE REGISTRIES ==========
    ("NPM Token", r"(?i)//registry\.npmjs\.org/:_authToken=[0-9a-f-]{36}", "high", "high", "secret", None),
    ("PyPI Token", _token("pypi-AgEIcHlwaS5vcmc", r"[A-Za-z0-9-_]{50,}"), "high", "high", "secret", None),
    ("Docker Hub Token", _token("dckr_pat_", r"[A-Za-z0-9_-]{27}"), "high", "high", "secret", None),
    ("Clojars API Token", _token("CLOJARS_", r"[a-zA-Z0-9]{60}"), "high", "high", "secret", None),
    ("RubyGems API Token", _token("rubygems_", r"[a-f0-9]{48}"), "high", "high", "secret", None),
    ("NuGet API Key", _token("oy2", r"[a-z0-9]{43}"), "high", "high", "secret", None),

    # ========== MODERN JS / SERVERLESS ECOSYSTEM ==========
    ("Clerk Secret Key", _token("sk_live_", r"[a-zA-Z0-9]{27,}"), "critical", "high", "auth", None),
    ("Clerk Publishable Key", _token("pk_live_", r"[a-zA-Z0-9]{27,}"), "low", "high", "auth", None),
    ("Clerk Test Secret Key", _token("sk_test_", r"[a-zA-Z0-9]{27,}"), "medium", "high", "auth", None),
    ("Neon DB Connection String", r"\bpostgresql://[^\s'\"]*@[^\s'\"]*\.neon\.tech/[^\s'\"]+", "high", "high", "secret", None),
    ("Upstash Redis REST Token", r"(?i)upstash[^\n]{0,120}?['\"]AX[a-zA-Z0-9_-]{36,}['\"]", "high", "medium", "secret", None),
    ("Upstash Redis REST URL", r"https://[a-z0-9-]+\.upstash\.io", "medium", "high", "infrastructure", None),
    # Left boundary: `re_` + 20 also ends `configure_...` / `prepare_...`
    # identifiers (13 hits on 300 clean library files, none a key).
    ("Resend API Key", r"(?<![A-Za-z0-9_])re_[a-zA-Z0-9]{20,}", "high", "high", "auth", None),
    ("Convex Deploy Key", r"(?:prod|dev):[a-z0-9]+:[a-zA-Z0-9_-]{40,}", "high", "high", "secret", None),
    ("Turso DB Token", r"(?i)turso[^\n]{0,120}?eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "high", "medium", "secret", None),
    ("Trigger.dev API Key", _token("tr_", r"(?:dev|prod|test)_[a-zA-Z0-9]{24,}"), "high", "high", "secret", None),
    ("Axiom API Token", _token("xaat-", r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"), "high", "high", "js_service", None),
    ("Axiom Ingest Token", _token("xait-", r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"), "high", "high", "js_service", None),
    ("Pinecone API Key", _token("pcsk_", r"[a-zA-Z0-9_]{50,}"), "high", "high", "ai_llm", None),
    ("Pinecone Legacy API Key", r"(?i)pinecone[^\n]{0,120}?['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]", "high", "medium", "ai_llm", None),
    ("Weaviate API Key", r"(?i)weaviate[^\n]{0,120}?['\"][a-zA-Z0-9]{40,}['\"]", "high", "medium", "ai_llm", None),
    ("Cloudinary URL", r"cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+", "high", "high", "cloud", None),
    ("Cloudinary API Secret", r"(?i)cloudinary[^\n]{0,120}?(?:api_?secret|secret)[^\n]{0,120}?['\"][a-zA-Z0-9_-]{27}['\"]", "high", "medium", "cloud", None),
    ("WorkOS API Key", _token("sk_", r"(?:live|test)_[a-zA-Z0-9]{30,}"), "high", "high", "auth", None),
    ("Liveblocks Secret Key", _token("sk_", r"(?:prod|dev)_[a-zA-Z0-9_-]{30,}"), "high", "high", "auth", None),
    ("Sanity Project Token", _token("sk", r"[a-zA-Z0-9]{8,}\.(?:production|dataset)\.[a-zA-Z0-9]+"), "high", "high", "auth", None),
    ("Expo Access Token", _token("expo_", r"[a-zA-Z0-9]{40,}"), "high", "high", "auth", None),
    ("Sentry Auth Token (new)", _token("sntrys_eyJ", r"[a-zA-Z0-9+/=_-]{80,}"), "high", "high", "js_service", None),

    # ========== GENERAL SECRETS (Medium) ==========
    ("JWT Token", _token("eyJ", r"[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"), "medium", "high", "secret", None),
    ("Basic Auth Header", r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]+", "high", "medium", "secret", None),
    ("Bearer Token", r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}", "high", "medium", "secret", None),
    ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "critical", "high", "secret", None),
    ("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "critical", "high", "secret", None),
    ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "critical", "high", "secret", None),
    ("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "critical", "high", "secret", None),
    ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "critical", "high", "secret", None),
    ("Generic Private Key", r"-----BEGIN PRIVATE KEY-----", "critical", "high", "secret", None),
    # A certificate is public, so info. The name and category stay: the
    # finding id hashes the name, and mutes, verdicts and node-filter rules
    # attach to that id.
    ("PKCS12 Certificate", r"-----BEGIN CERTIFICATE-----", "info", "medium", "secret", None),
    ("MongoDB URI", r"\bmongodb(?:\+srv)?://[^\s'\"]+", "high", "high", "secret", None),
    ("PostgreSQL URI", r"\bpostgres(?:ql)?://[^\s'\"]+", "high", "high", "secret", None),
    ("MySQL URI", r"\bmysql://[^\s'\"]+", "high", "high", "secret", None),
    ("Redis URL", r"\bredis://[^\s'\"]+", "high", "high", "secret", None),
    ("CockroachDB URL", r"\bcockroachdb://[^\s'\"]+", "high", "high", "secret", None),
    # The password is judged like a generic value (_GENERIC_VALUE_RE), so
    # `user:password@`, `${PASS}` and `<pass>` placeholders stay silent.
    ("Credentials in URL", r"\b(?:https?|ftp|amqps?|smtp)://[^\s:/@'\"]{1,64}:[^\s@'\"]{1,128}@[^\s/'\"]+", "high", "medium", "secret", None),
    ("JDBC with password", r"(?i)jdbc:[a-z0-9]+:[^\s'\"]{0,512}?(?:password|pwd)=[^\s;&'\"]+", "high", "high", "secret", None),
    ("Generic API Key", r"(?i)(api[_-]?key|apikey|api_secret)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?", "medium", "low", "secret", None),
    ("Generic Secret", r"(?i)(secret|password|passwd|pwd)[\"']?\s*[:=]\s*[\"'][^\"']{8,}[\"']", "medium", "low", "secret", None),
    ("Generic Token", r"(?i)(access[_-]?token|auth[_-]?token)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?", "medium", "low", "secret", None),
    ("Hardcoded Password", r"(?i)(password|passwd|pwd)\s*=\s*[\"'][^\"']{4,}[\"']", "medium", "low", "secret", None),

    # ========== INFRASTRUCTURE (Medium) ==========
    ("S3 Bucket (path-style)", r"https?://s3(?:[.-][\w-]+)?\.amazonaws\.com/([a-zA-Z0-9._-]+)", "medium", "high", "infrastructure", None),
    ("S3 Bucket (virtual-hosted)", r"https?://([a-zA-Z0-9._-]+)\.s3(?:[.-][\w-]+)?\.amazonaws\.com", "medium", "high", "infrastructure", None),
    ("S3 ARN", r"arn:aws:s3:::([a-zA-Z0-9._-]+)", "medium", "high", "infrastructure", None),
    ("GCP Storage", r"https?://storage\.googleapis\.com/([a-zA-Z0-9._-]+)", "medium", "high", "infrastructure", None),
    ("GCP gs:// URL", r"gs://([a-zA-Z0-9._-]+)", "medium", "high", "infrastructure", None),
    ("Azure Blob Storage", r"https?://([a-zA-Z0-9]+)\.blob\.core\.windows\.net", "medium", "high", "infrastructure", None),
    # The keyword must be a word of a host label, alone or in a common compound
    # (`dev.`, `api-dev.`, `devapi.`, `testing.`, `adminpanel.`, `localdev.`);
    # `developer.`, `latest.`, `contest.` and `localhost` do not match.
    ("Internal/Staging URL", r"(?i)https?://[a-z0-9.-]*?(?<![a-z])(?:local|api|app|web)?(staging|stage|internal|dev(?:elopment)?|test(?:s|ing)?|local|admin)(?:api|app|panel|portal|web)?(?![a-z])[a-z0-9.-]*\.[a-z]{2,}", "low", "low", "infrastructure", None),
    ("Localhost with Port", r"(?:localhost|127\.0\.0\.1):\d{2,5}", "low", "medium", "infrastructure", None),

    # ========== LOW / INFO ==========
    ("Email Address", r"[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,24}", "info", "low", "info", None),
    ("Private IP (RFC1918)", r"(?:^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})(?:[^0-9]|$)", "low", "medium", "info", None),
    ("UUID v4", r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", "info", "low", "info", None),
    ("Debug Flag", r"(?i)(debug|NODE_ENV)\s*[:=]\s*['\"]?(true|development|1)['\"]?", "low", "medium", "info", None),
]

#: Names a scan writes that no pattern above carries: a hit re-read from its
#: value or label (see `_refine`).
DERIVED_SECRET_NAMES = (
    "Algolia Search Key",
    "Supabase anon key",
    "Supabase service_role key",
)

#: Keys that are PUBLIC BY DESIGN: they ship to every browser that loads the
#: page, and the service limits what they can do. Written as Secret findings at
#: severity info with `public_client_key`, never dropped: an unrestricted
#: Google key can still be spent on a paid API. Exact names, mirrored
#: (lowercased) by score_model.PUBLIC_CLIENT_KEY_TYPES and the webapp's
#: publicClientKeys.ts; tests pin the three equal.
PUBLIC_CLIENT_KEY_NAMES = frozenset({
    "GCP API Key",
    "Firebase API Key",
    "Segment Write Key",
    "Amplitude API Key",
    "New Relic Browser API Token",
    "Sentry DSN",
    "Stripe Publishable Key",
    "Google reCAPTCHA Key",
    "Mapbox Token",
    "Algolia App ID",
    "Algolia Search Key",
    "Intercom App ID",
    "Pusher Key",
    "Clerk Publishable Key",
    "Mailgun Public Key",
    "Flutterwave Public Key",
    "Supabase anon key",
    "Supabase Publishable Key",
})

#: Rules that report only what TruffleHog confirmed, when TruffleHog ran: each
#: had false positives on clean code, TruffleHog detects its key type at 99% or
#: more, and it has no precise provider prefix (TruffleHog plan, step 2.3, with
#: the numbers). A hit TruffleHog matched stays, with its own id; with
#: TruffleHog off, failed or missing the rule reports as before.
SUPERSEDED_BY_TRUFFLEHOG = frozenset({
    "Travis CI Token",  # 3 hits on 300 clean library files; TravisCI detects 99.5%
})

# A search-only Algolia key has the admin key's format; only its label tells
# them apart, so an unlabelled key stays the (high) API key.
_ALGOLIA_SEARCH_LABEL = re.compile(
    r'(?i)search[_-]?(?:only[_-]?)?(?:api[_-]?)?key["\']?\s*[:=]\s*["\'][a-f0-9]{32}["\']$')

#: A JWT's payload is read only up to this size; the token is target-controlled.
_JWT_PAYLOAD_MAX = 4096
_JWT = re.compile(r'eyJ[A-Za-z0-9_-]+\.(eyJ[A-Za-z0-9_-]+)\.[A-Za-z0-9_-]*')
_JWT_HEADER_AT_END = re.compile(r'eyJ[A-Za-z0-9_-]+$')
_JWT_REST = re.compile(r'\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

_SIGNED_DATE = re.compile(r'X-(?:Amz|Goog)-Date=(\d{8}T\d{6}Z)')
_SIGNED_EXPIRES = re.compile(r'X-(?:Amz|Goog)-Expires=(\d{1,7})(?!\d)')


def _jwt_role(token: str):
    """The `role` claim of a JWT, or None. The payload is base64url-decoded,
    never verified; anything unreadable or oversized is "role unknown"."""
    m = _JWT.fullmatch(token or '')
    if not m or len(m.group(1)) > _JWT_PAYLOAD_MAX:
        return None
    payload = m.group(1)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    except (ValueError, TypeError):
        return None
    role = claims.get('role') if isinstance(claims, dict) else None
    return role if isinstance(role, str) else None


def _supabase_token(name: str, matched_text: str, tail: str):
    """The whole JWT a Supabase-key or JWT hit names. The Supabase pattern
    stops at the token's header, so the rest comes from the text after it."""
    if name == 'JWT Token':
        return matched_text
    head = _JWT_HEADER_AT_END.search(matched_text)
    rest = _JWT_REST.match(tail)
    return head.group(0) + rest.group(0) if head and rest else None


def _signed_url_expired(url: str, now=None) -> bool:
    date, expires = _SIGNED_DATE.search(url), _SIGNED_EXPIRES.search(url)
    if not (date and expires):
        return False
    try:
        signed = datetime.strptime(date.group(1), '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return signed + timedelta(seconds=int(expires.group(1))) < (now or datetime.now(timezone.utc))


def _refine(name: str, matched_text: str, tail: str = '') -> dict:
    """What a hit's value or label says beyond the pattern that matched it:
    a different `name`, `severity` or `confidence`, and for a JWT the `jwt`
    itself, which makes the Supabase pattern and the JWT pattern one finding.
    `tail` is the text right after the match."""
    if name == 'Algolia API Key' and _ALGOLIA_SEARCH_LABEL.search(matched_text):
        return {'name': 'Algolia Search Key'}
    if name in ('Supabase Key', 'JWT Token'):
        token = _supabase_token(name, matched_text, tail)
        role = _jwt_role(token) if token else None
        if role == 'service_role':
            # It bypasses row-level security: the project's whole database.
            return {'name': 'Supabase service_role key', 'severity': 'critical',
                    'confidence': 'high', 'jwt': token}
        if role == 'anon':
            return {'name': 'Supabase anon key', 'jwt': token}
    if name == 'Signed URL in client code' and _signed_url_expired(matched_text):
        return {'severity': 'low'}
    return {}


# Pre-compile all patterns at module load time
JS_SECRET_PATTERNS = []
for name, regex, severity, confidence, category, validator_ref in _RAW_PATTERNS:
    try:
        compiled = re.compile(regex)
        JS_SECRET_PATTERNS.append({
            'name': name,
            'regex': compiled,
            'severity': severity,
            'confidence': confidence,
            'category': category,
            'validator_ref': validator_ref,
        })
    except re.error:
        print(f"[!][JsRecon] Failed to compile pattern: {name}")

# Email false positive domains to filter out
_EMAIL_FILTER_DOMAINS = {
    'example.com', 'test.com', 'localhost', 'email.com',
    'domain.com', 'company.com', 'yourcompany.com',
    'placeholder.com', 'sample.com', 'fake.com',
    'sentry.io', 'w3.org',
}

# Dev comment patterns
DEV_COMMENT_KEYWORDS = [
    'TODO', 'FIXME', 'HACK', 'XXX', 'BUG', 'TEMP', 'REMOVEME',
    'WORKAROUND', 'DEPRECATED', 'REFACTOR',
]

DEV_COMMENT_SENSITIVE_KEYWORDS = [
    'password', 'secret', 'key', 'token', 'credential',
    'admin', 'debug', 'bypass', 'hardcod', 'temporary',
]

_DEV_COMMENT_RE = re.compile(
    r'(?://|/\*|\*)\s*(?:' +
    '|'.join(DEV_COMMENT_KEYWORDS) +
    r')[\s:]+(.{1,200})',
    re.IGNORECASE
)

_SENSITIVE_KEYWORD_RE = re.compile('|'.join(DEV_COMMENT_SENSITIVE_KEYWORDS), re.IGNORECASE)
_COMMENT_MARKER_RE = re.compile(r'//|/\*|\*')


def _sensitive_comment(line: str):
    """The text from the line's first comment marker to its end, when a
    sensitive keyword follows that marker; else None.

    The same match as ``(?://|/\\*|\\*)\\s*.*(keyword).*``, found in linear
    time: that regex ran ``.*`` to the end of the line from every ``*`` and
    backtracked, the square of the length of a one-line minified bundle. The
    first marker ends earliest, so a keyword starting after it is all it takes.
    """
    last = None
    for last in _SENSITIVE_KEYWORD_RE.finditer(line):
        pass
    if last is None:
        return None
    marker = _COMMENT_MARKER_RE.search(line)
    if marker is None or marker.end() > last.start():
        return None
    return line[marker.start():]

# Confidence ordering for filtering
CONFIDENCE_ORDER = {'high': 3, 'medium': 2, 'low': 1}
SEVERITY_ORDER = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}


def _make_finding_id(name: str, matched_text: str, source_url: str) -> str:
    """Generate a deterministic ID for deduplication."""
    raw = f"{name}:{matched_text}:{source_url}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _is_false_positive_email(email: str) -> bool:
    """Filter out placeholder/test email addresses."""
    domain = email.split('@')[-1].lower()
    return domain in _EMAIL_FILTER_DOMAINS


# ---------------------------------------------------------------------------
# False-positive filters for embedded binary / font / base64 data
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy. Real secrets > 3.5, binary junk < 3.0."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


_BASE64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')


#: How far a base64 run must reach past the match before the match counts as
#: sitting inside it. Measuring the run alone made every match over the
#: threshold (a JWT, a Bearer header, a 1Password service token) its own blob.
_BLOB_MIN_OUTSIDE = 64


def _is_inside_base64_blob(line: str, start: int, end: int, threshold: int = 200) -> bool:
    """Check if match sits inside a continuous base64-like run > threshold chars."""
    left = start
    while left > 0 and line[left - 1] in _BASE64_CHARS:
        left -= 1
    right = end
    while right < len(line) and line[right] in _BASE64_CHARS:
        right += 1
    outside = (start - left) + (right - end)
    return (right - left) > threshold and outside > _BLOB_MIN_OUTSIDE


_BINARY_CONTEXT_RE = re.compile(
    r'glyf|loca|hhea|hmtx|GSUB|cmap|IcoMoon|woff|font-face|@font-face|'
    r'data:application/font|data:font/|base64,|opentype|truetype|'
    r'data:application/x-font|\.eot|\.ttf|\.woff|FontFace|fontFamily',
    re.IGNORECASE,
)


def _has_binary_context(context: str) -> bool:
    """Check if surrounding code contains font/binary data indicators."""
    return bool(_BINARY_CONTEXT_RE.search(context))


def _has_repetitive_pattern(text: str) -> bool:
    """Detect strings with suspiciously repetitive chars (e.g., 'AAAAAA...')."""
    if len(text) < 16:
        return False
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    max_freq = max(freq.values())
    if max_freq / len(text) > 0.4:
        return True
    # Check for runs of 6+ identical characters
    for i in range(len(text) - 5):
        if len(set(text[i:i + 6])) == 1:
            return True
    return False


_STAGING_URL_WHITELIST = {
    'developer.mozilla.org', 'docs.microsoft.com', 'learn.microsoft.com',
    'w3.org', 'stackoverflow.com', 'github.com', 'devdocs.io',
    'developer.apple.com', 'developers.google.com', 'reactjs.org',
    'nodejs.org', 'npmjs.com', 'pypi.org',
}


def _is_whitelisted_staging_url(matched_text: str) -> bool:
    """Filter known non-interesting domains from Internal/Staging URL pattern."""
    lower = matched_text.lower()
    return any(domain in lower for domain in _STAGING_URL_WHITELIST)


# The keyword-anchored patterns match any `password: "..."` in a bundle, and a
# bundle is mostly UI: labels ("Forgot your password?"), routes, i18n keys,
# selectors and field names. These rules judge the captured VALUE, never the
# line, so a real secret next to such text still reports.
_GENERIC_VALUE_RE = {
    'Generic Secret': re.compile(r'[:=]\s*["\']([^"\']*)["\']'),
    'Hardcoded Password': re.compile(r'=\s*["\']([^"\']*)["\']'),
    'Generic API Key': re.compile(r'[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})'),
    'Generic Token': re.compile(r'[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})'),
    'Credentials in URL': re.compile(r'://[^\s:/@\'"]{1,64}:([^\s@\'"]{1,128})@'),
}
_PLACEHOLDER_VALUE = re.compile(
    r'^(?:x{3,}|\*{3,}|\.{3,}|changeme|change[_-]?me|example|sample|dummy|placeholder|test|testing'
    r'|todo|tbd|none|null|undefined|true|false|password|passwd|secret|token|api[_-]?key'
    r'|(?:your|enter)[_-]\w+|my[_-]?(?:key|token|secret|password|api[_-]?key)'
    r'|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%\w+%|__\w+__)$',
    re.IGNORECASE,
)
_I18N_KEY = re.compile(r'^[A-Za-z_]+(?:\.[A-Za-z_]+)+$')
# Shapes that are code, not a secret: a route, a CSS selector, an env-var or
# template reference, markup. A credential that merely STARTS with $ or #
# (`$Pr0d-Db!2024`) has none of these shapes and is kept.
_CODE_SHAPED_VALUE = re.compile(
    r'^(?:/[a-z0-9_\-.~]*(?:/[\w\-.~]*)+(?:\?[\w\-=&%.]*)?'  # a multi-segment route
    r'|/[a-z0-9_\-.~]+(?:\?[\w\-=&%.]*)?'                      # a lower-case one-segment route
    r'|[#.][A-Za-z][A-Za-z_-]*'        # #id / .class (a digit mix reads as a password)
    r'|\[[^\]]+\]'                     # [name=password]
    r'|\$[A-Z_][A-Z0-9_]*'              # $ENV_VAR (upper case, by convention)
    r'|<[^>]*>)$'                     # markup
)
# A CSS-modules class name: `<Component>_<class>__<hash>` (Next.js), or
# css-loader's `___` / `--` forms. A build names a form field's class after the
# field, so `password: "LoginForm_password__3xYz9"` is a selector, not a
# password. Tested only on short values: the nested quantifiers would backtrack
# quadratically on a long one, and a class name is never long.
_CSS_MODULE_CLASS = re.compile(r'^[A-Za-z][\w-]*_[\w-]+(?:__|--)[\w-]{5}$')
_CSS_MODULE_CLASS_MAX = 128
# A base64 secret is not a route even when it starts with "/": it has no
# lower-case path words between its slashes and usually ends in "=".
_BASE64ISH = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
_FIELD_NAME_WORDS = ('password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'api-key')


def _generic_value_is_noise(name: str, matched_text: str) -> bool:
    """True when a generic keyword pattern captured UI text, a placeholder,
    a route/selector/template, an i18n key, a field name or an identifier
    rather than a credential."""
    value_re = _GENERIC_VALUE_RE.get(name)
    if value_re is None:
        return False
    m = value_re.search(matched_text)
    value = (m.group(1) if m else '').strip()
    if not value:
        return True
    # UI text is prose: words without digits, or a sentence. A passphrase like
    # "Summer 2024!" has a space too, and is kept.
    if any(c.isspace() for c in value) and (not re.search(r'\d', value) or len(value.split()) >= 3):
        return True
    if _PLACEHOLDER_VALUE.match(value) or _I18N_KEY.match(value):
        return True
    if _CODE_SHAPED_VALUE.match(value) and not _BASE64ISH.match(value):
        return True
    if len(value) <= _CSS_MODULE_CLASS_MAX and _CSS_MODULE_CLASS.match(value):
        return True
    if '${' in value or '://' in value:
        return True
    if re.fullmatch(r'[A-Za-z_-]+', value) and any(w in value.lower() for w in _FIELD_NAME_WORDS):
        return True
    if name in ('Generic API Key', 'Generic Token') and _looks_like_identifier(value):
        # `getApiKeyFromStorageService` names a key; a random one has no words.
        return True
    return False


def _looks_like_identifier(value: str) -> bool:
    """A letters-only value made of word-like parts (camelCase, snake_case,
    kebab-case or one long word), as opposed to random letters, whose parts
    are short and often vowel-less."""
    if not re.fullmatch(r'[A-Za-z_-]+', value):
        return False
    parts = [p for p in re.split(r'[_-]|(?<=[a-z])(?=[A-Z])', value) if p]
    if not parts:
        return False
    with_vowel = sum(1 for p in parts if re.search(r'[aeiouAEIOU]', p))
    return sum(len(p) for p in parts) / len(parts) >= 3.5 and with_vowel / len(parts) >= 0.8


#: Keyword rules that name no provider. When one's match holds a provider
#: rule's (`apiKey: "AIza..."`), the provider rule says what the value is.
_GENERIC_NAMES = frozenset({'Generic API Key', 'Generic Token', 'Generic Secret', 'Hardcoded Password'})

#: Markers that are a private key only with key data after them: in library
#: code they open a parser branch or a runtime template (`"...KEY-----\n" + n`).
_PEM_KEY_NAMES = frozenset({
    'RSA Private Key', 'DSA Private Key', 'EC Private Key', 'OpenSSH Private Key',
    'PGP Private Key', 'Generic Private Key',
})
_PEM_MIN_KEY_CHARS = 64
_PEM_LOOKAHEAD = 4000
_PEM_EDGE_CHARS = ' \t"\'`+,;()'
_PEM_ARMOR_HEADER = re.compile(r'^[A-Za-z][A-Za-z-]*:\s')
_BASE64_RUN = re.compile(r'[A-Za-z0-9+/=]+')

#: Loose rules that report only with their provider's word in the given
#: number of characters before the match. `YC` + 38 is also a webpack chunk
#: id, and the "AWS" in the name made each such hit a top-tier credential.
_REQUIRES_NEARBY = {
    'Yandex AWS Access Token': (re.compile(r'(?i)yandex'), 120),
}

_UUID4 = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.IGNORECASE)


def _has_key_data(after: str) -> bool:
    """True when at least _PEM_MIN_KEY_CHARS base64 characters follow a PEM
    marker, through the ways JS writes a key: escaped `\\n`, string quotes,
    `+` concatenation over the next lines, and PGP armor headers."""
    text = after[:_PEM_LOOKAHEAD].replace('\\r', '\n').replace('\\n', '\n').replace('\r', '\n')
    run = 0
    started = False
    for piece in text.split('\n'):
        piece = piece.strip(_PEM_EDGE_CHARS)
        if not piece:
            continue
        if not started and _PEM_ARMOR_HEADER.match(piece):
            continue
        started = True
        m = _BASE64_RUN.match(piece)
        run += len(m.group(0)) if m else 0
        if run >= _PEM_MIN_KEY_CHARS:
            return True
        if not m or m.end() < len(piece):
            return False
    return False


_PEM_BLOCK = re.compile(r'-----BEGIN [A-Z0-9 ]*-----.*?-----END [A-Z0-9 ]*-----', re.S)
_PEM_BLOCK_MAX = 16000


def secret_value_of(name: str, matched_text: str, after: str = '') -> str:
    """The key itself out of a match: the quoted value of a keyword rule
    (`password = "x"` gives `x`), the whole PEM block for a key rule that
    matched only its header (`after` is the text from the header on), else the
    match without the quotes a rule caught around it."""
    if name in _PEM_KEY_NAMES and after:
        block = _PEM_BLOCK.match(after[:_PEM_BLOCK_MAX])
        if block:
            return block.group(0)
    value_re = _GENERIC_VALUE_RE.get(name)
    m = value_re.search(matched_text) if value_re else None
    value = m.group(1).strip() if m else ''
    return (value or matched_text.strip().strip('"\'`')) or matched_text


def _generic_value_is_uuid(name: str, matched_text: str) -> bool:
    """A generic rule whose value is a bare UUIDv4: a config, feature-flag or
    object id with no provider authority behind it."""
    value_re = _GENERIC_VALUE_RE.get(name) if name in _GENERIC_NAMES else None
    m = value_re.search(matched_text) if value_re else None
    return bool(m) and bool(_UUID4.match(m.group(1).strip()))


def _drop_generic_overlaps(findings: list) -> list:
    """A generic finding whose span holds a provider finding's span on the same
    line is that provider's key: drop it and name it on the provider finding.
    Generic never beats generic and specific never beats specific, so a
    Gemini key keeps its critical rule beside the public GCP one."""
    specific: dict = {}
    for f in findings:
        if f['name'] not in _GENERIC_NAMES and f['category'] not in _UNMASKED_CATEGORIES:
            specific.setdefault((f['source_url'], f['line_number']), []).append(f)
    if not specific:
        return findings
    kept = []
    for f in findings:
        if f['name'] in _GENERIC_NAMES:
            start, end = f['_span']
            inside = [s for s in specific.get((f['source_url'], f['line_number']), [])
                      if start <= s['_span'][0] and s['_span'][1] <= end]
            if inside:
                winner = max(inside, key=_collapse_rank)
                names = winner.setdefault('alternate_names', [])
                for name in [f['name']] + f.get('alternate_names', []):
                    if name not in names and name != winner['name']:
                        names.append(name)
                continue
        kept.append(f)
    return kept


def _collapse_rank(f: dict) -> tuple:
    """Higher severity > higher confidence > the match that IS the token >
    longer pattern name (specificity proxy)."""
    return (
        SEVERITY_ORDER.get(f['severity'], 0),
        CONFIDENCE_ORDER.get(f['confidence'], 0),
        f.get('_jwt') is not None and f['matched_text'] == f['_jwt'],
        len(f['name']),
    )


def _collapse_span_duplicates(findings: list) -> list:
    """Collapse findings that matched the same span under different pattern names.

    When overlapping prefix patterns (e.g. Stripe/Clerk/WorkOS all claim sk_live_*)
    hit the same token, keep the highest-ranked finding as primary and record the
    rest in `alternate_names` so no information is lost.
    """
    if not findings:
        return findings

    groups: dict = {}
    order: list = []
    for f in findings:
        # A Supabase key matches both the Supabase pattern (up to the token's
        # header) and the JWT pattern (the token): one key, one finding.
        if f.get('_jwt'):
            key = ('jwt', f['_jwt'], f['source_url'], f['line_number'])
        else:
            key = (f['matched_text'], f['source_url'], f['line_number'])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    collapsed = []
    for key in order:
        group = groups[key]
        if len(group) == 1:
            collapsed.append(group[0])
            continue
        group.sort(key=_collapse_rank, reverse=True)
        primary = group[0]
        primary['alternate_names'] = [f['name'] for f in group[1:]]
        collapsed.append(primary)

    return _drop_generic_overlaps(collapsed)


# ---------------------------------------------------------------------------
# Long-line windowing
# ---------------------------------------------------------------------------
# Minified bundles put the whole file on a single line. Rather than skip such
# lines (which silently drops every secret in the bundle), scan them in
# overlapping windows: each regex call stays small -- so a hostile target
# cannot trigger catastrophic backtracking (ReDoS) -- and nothing is left
# unscanned regardless of file size. The overlap must exceed the longest
# possible match so a secret straddling a window boundary is still fully
# contained in the next window. The largest bounded pattern is the Next.js Env
# Leak (`.{0,5000}`), hence a 5k overlap.
_MAX_SCAN_LINE_LEN = 100_000
_WINDOW_OVERLAP = 5_000


def _window_line(line: str, size: int = _MAX_SCAN_LINE_LEN,
                 overlap: int = _WINDOW_OVERLAP) -> list:
    """Split an over-long line into overlapping windows of `size` chars, as
    (offset in the line, text).

    Consecutive windows advance by (size - overlap) so any match up to `overlap`
    chars long is fully contained in at least one window. Duplicate hits in the
    overlap region are collapsed downstream by the finding-id dedup.
    """
    step = size - overlap
    segments = []
    start = 0
    n = len(line)
    while start < n:
        segments.append((start, line[start:start + size]))
        if start + size >= n:
            break
        start += step
    return segments


# ---------------------------------------------------------------------------
# The context stored with each finding
# ---------------------------------------------------------------------------
#: The longest context a finding carries; the graph writer caps it here too.
CONTEXT_MAX_CHARS = 400
_CONTEXT_SIDE = 150
#: Above this a line is minified code: the context is a character window
#: around the match, since the surrounding LINES may be the whole bundle.
_CONTEXT_LONG_LINE = 1000
#: Matches of these categories are not credentials (an email, a private IP, a
#: bucket URL, a staging host) and stay readable in a context.
_UNMASKED_CATEGORIES = frozenset({'info', 'infrastructure'})


def redact(text: str) -> str:
    """The stored form of a secret: its first and last characters only."""
    if len(text) > 12:
        return text[:6] + '...' + text[-4:]
    if len(text) > 4:
        return text[:3] + '...'
    return '***'


def _merge_spans(spans: list) -> list:
    merged: list = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def _render(text: str, start: int, end: int, spans: list, focus: int = -1) -> tuple:
    """text[start:end] with every span touching it replaced by its redacted
    form, WHOLE: a key the window edge cuts in half is masked, not left as a
    fragment no pattern would recognise. Returns (rendered, where the span or
    character at `focus` begins in it, or -1)."""
    out: list = []
    size = 0
    mark = -1
    pos = start
    for s, e in spans:
        if e <= start:
            continue
        if s >= end:
            break
        if s > pos:
            if pos <= focus < s:
                mark = size + focus - pos
            out.append(text[pos:s])
            size += s - pos
        if s <= focus < e:
            mark = size
        masked = redact(text[s:e])
        out.append(masked)
        size += len(masked)
        pos = e
    if pos < end:
        if pos <= focus < end:
            mark = size + focus - pos
        out.append(text[pos:end])
    return ''.join(out), mark


def _finding_context(lines: list, spans_by_line: dict, line_num: int,
                     start: int, end: int) -> str:
    """The text around a match, every secret-shaped span in it masked.

    A long line gets a character window of about 150 characters either side;
    a short one keeps its neighbour lines (their nearest 150 characters). The
    result is trimmed to CONTEXT_MAX_CHARS around the match.
    """
    idx = line_num - 1
    line = lines[idx]
    if len(line) > _CONTEXT_LONG_LINE:
        context, mark = _render(line, max(0, start - _CONTEXT_SIDE),
                                min(len(line), end + _CONTEXT_SIDE),
                                spans_by_line.get(line_num, []), focus=start)
    else:
        parts: list = []
        offset = 0
        if idx > 0:
            prev = lines[idx - 1]
            text, _ = _render(prev, max(0, len(prev) - _CONTEXT_SIDE), len(prev),
                              spans_by_line.get(line_num - 1, []))
            parts.append(text + '\n')
            offset = len(parts[0])
        text, mark = _render(line, 0, len(line), spans_by_line.get(line_num, []), focus=start)
        parts.append(text)
        mark = offset + mark if mark >= 0 else -1
        if idx + 1 < len(lines):
            nxt = lines[idx + 1]
            text, _ = _render(nxt, 0, min(len(nxt), _CONTEXT_SIDE),
                              spans_by_line.get(line_num + 1, []))
            parts.append('\n' + text)
        context = ''.join(parts)
    if len(context) > CONTEXT_MAX_CHARS:
        centre = mark if mark >= 0 else 0
        cut = max(0, min(centre - CONTEXT_MAX_CHARS // 2, len(context) - CONTEXT_MAX_CHARS))
        context = context[cut:cut + CONTEXT_MAX_CHARS]
    return context


def scan_js_content(
    content: str,
    source_url: str,
    custom_patterns: Optional[list] = None,
    min_confidence: str = 'low',
) -> tuple[list, dict]:
    """
    Scan JavaScript content for secrets using hardcoded + optional custom patterns.

    Args:
        content: JavaScript file content
        source_url: URL the JS file was downloaded from
        custom_patterns: Optional list of dicts with keys: name, regex, severity, confidence, category
        min_confidence: Minimum confidence level to include ('low', 'medium', 'high')

    Returns:
        Tuple of (findings list, filtered_counts dict).
        Each finding dict has: id, name, matched_text, severity, confidence,
        category, line_number, source_url, validator_ref
    """
    findings = []
    seen_hashes = set()
    min_conf_val = CONFIDENCE_ORDER.get(min_confidence, 1)
    filtered_counts = {
        'low_entropy': 0,
        'base64_blob': 0,
        'binary_context': 0,
        'repetitive': 0,
        'url_whitelist': 0,
        'generic_noise': 0,
        'no_key_data': 0,
        'no_keyword_nearby': 0,
    }

    # Categories where false-positive filters apply
    _FP_FILTER_CATEGORIES = {'auth', 'cloud', 'payment', 'secret', 'js_service', 'ai_llm'}
    # Patterns that rely on structural prefixes, not randomness -- skip entropy check
    _SKIP_ENTROPY_KEYWORDS = ('Private Key', 'URL', 'URI', 'DSN', 'Header')

    # Merge custom patterns if provided
    patterns = list(JS_SECRET_PATTERNS)
    if custom_patterns:
        for cp in custom_patterns:
            try:
                compiled = re.compile(cp['regex']) if isinstance(cp.get('regex'), str) else cp.get('regex')
                patterns.append({
                    'name': cp.get('name', 'Custom Pattern'),
                    'regex': compiled,
                    'severity': cp.get('severity', 'medium'),
                    'confidence': cp.get('confidence', 'medium'),
                    'category': cp.get('category', 'custom'),
                    'validator_ref': cp.get('validator_ref'),
                })
            except (re.error, TypeError, KeyError):
                continue

    lines = content.split('\n')

    # Precompute scan units once (shared across every pattern). Over-long
    # minified lines are broken into overlapping windows so each regex call
    # stays small (ReDoS-safe) and no content is skipped; normal lines pass
    # through untouched. Line numbers still refer to the original file line.
    scan_units = []  # list of (line_num, offset in the line, segment_text)
    for line_num, line in enumerate(lines, 1):
        if len(line) > _MAX_SCAN_LINE_LEN:
            for offset, segment in _window_line(line):
                scan_units.append((line_num, offset, segment))
        else:
            scan_units.append((line_num, 0, line))

    # Every secret-shaped span per line, so each context can mask its
    # neighbours too: a minified line often holds several keys. Collected from
    # matches the filters below drop as well (a low-entropy or below-threshold
    # key is still not something to print), never from generic-keyword noise.
    spans_by_line: dict = {}

    for pattern in patterns:
        reportable = CONFIDENCE_ORDER.get(pattern['confidence'], 1) >= min_conf_val
        maskable = pattern['category'] not in _UNMASKED_CATEGORIES
        if not reportable and not maskable:
            continue

        for line_num, offset, line in scan_units:
            for match in pattern['regex'].finditer(line):
                matched_text = match.group(0)
                noise = _generic_value_is_noise(pattern['name'], matched_text)
                if maskable and not noise and matched_text:
                    spans_by_line.setdefault(line_num, []).append(
                        (offset + match.start(), offset + match.end()))
                if not reportable:
                    continue

                # Skip email false positives
                if pattern['name'] == 'Email Address' and _is_false_positive_email(matched_text):
                    continue

                # Skip whitelisted staging URLs
                if pattern['name'] == 'Internal/Staging URL' and _is_whitelisted_staging_url(matched_text):
                    filtered_counts['url_whitelist'] += 1
                    continue

                if noise:
                    filtered_counts['generic_noise'] += 1
                    continue

                # --- False-positive filters for embedded binary/font data ---
                # Only apply to secret-type categories, not infrastructure/info
                if pattern['category'] in _FP_FILTER_CATEGORIES:
                    skip_entropy = any(kw in pattern['name'] for kw in _SKIP_ENTROPY_KEYWORDS)
                    if not skip_entropy and len(matched_text) >= 16 and _shannon_entropy(matched_text) < 3.0:
                        filtered_counts['low_entropy'] += 1
                        continue
                    if _is_inside_base64_blob(line, match.start(), match.end()):
                        filtered_counts['base64_blob'] += 1
                        continue
                    # Binary context check: only near the match on a long line,
                    # whatever the line count. A minified bundle after a short
                    # license header is one huge line, so one `fontFamily` on
                    # it would otherwise hide every secret.
                    if len(line) > 1000:
                        nearby = line[max(0, match.start() - 300):min(len(line), match.end() + 300)]
                    else:
                        nearby = line
                    if _has_binary_context(nearby):
                        filtered_counts['binary_context'] += 1
                        continue
                    if _has_repetitive_pattern(matched_text):
                        filtered_counts['repetitive'] += 1
                        continue

                full_line = lines[line_num - 1]
                abs_start, abs_end = offset + match.start(), offset + match.end()
                if pattern['name'] in _PEM_KEY_NAMES and not _has_key_data(
                        full_line[abs_end:abs_end + _PEM_LOOKAHEAD] + '\n'
                        + '\n'.join(lines[line_num:line_num + 2])):
                    filtered_counts['no_key_data'] += 1
                    continue
                nearby_rule = _REQUIRES_NEARBY.get(pattern['name'])
                if nearby_rule:
                    keyword, reach = nearby_rule
                    before = full_line[max(0, abs_start - reach):abs_start]
                    if len(before) < reach and line_num > 1:
                        before = (lines[line_num - 2] + '\n' + before)[-reach:]
                    if not keyword.search(before):
                        filtered_counts['no_keyword_nearby'] += 1
                        continue

                # Deduplicate by content hash. Keyed on the PATTERN's name, so a
                # hit `_refine` renames keeps the node id (and the mute,
                # verdict and fix item on it) it had before the rename.
                finding_id = _make_finding_id(pattern['name'], matched_text, source_url)
                if finding_id in seen_hashes:
                    continue
                seen_hashes.add(finding_id)

                refined = _refine(pattern['name'], matched_text,
                                  line[match.end():match.end() + _JWT_PAYLOAD_MAX + 200])
                name = refined.get('name', pattern['name'])
                public = name in PUBLIC_CLIENT_KEY_NAMES
                severity = refined.get('severity', pattern['severity'])
                if _generic_value_is_uuid(pattern['name'], matched_text):
                    severity = 'low'
                findings.append({
                    'id': finding_id,
                    'name': name,
                    'matched_text': matched_text,
                    'secret_value': secret_value_of(
                        pattern['name'], matched_text,
                        full_line[abs_start:abs_start + _PEM_BLOCK_MAX] + '\n'
                        + '\n'.join(lines[line_num:line_num + 60])
                        if pattern['name'] in _PEM_KEY_NAMES else ''),
                    'redacted_value': redact(matched_text),
                    'severity': 'info' if public else severity,
                    'public_client_key': public,
                    'confidence': refined.get('confidence', pattern['confidence']),
                    'category': pattern['category'],
                    'line_number': line_num,
                    'source_url': source_url,
                    'validator_ref': pattern['validator_ref'],
                    'detection_method': 'regex',
                    '_span': (offset + match.start(), offset + match.end()),
                    '_jwt': refined.get('jwt'),
                })

    findings = _collapse_span_duplicates(findings)
    spans_by_line = {n: _merge_spans(s) for n, s in spans_by_line.items()}
    for finding in findings:
        finding.pop('_jwt', None)
        start, end = finding.pop('_span')
        finding['context'] = _finding_context(lines, spans_by_line,
                                              finding['line_number'], start, end)
        # The same window with nothing masked, for the operator only: `context`
        # is what reviewers and models read.
        finding['raw_context'] = _finding_context(lines, {}, finding['line_number'], start, end)
    return findings, filtered_counts


def scan_dev_comments(content: str, source_url: str) -> list:
    """
    Extract developer comments containing sensitive keywords or TODO/FIXME markers.

    Returns:
        List of finding dicts with: type, content, source_url, line, severity
    """
    findings = []
    lines = content.split('\n')

    for line_num, line in enumerate(lines, 1):
        # Check for TODO/FIXME/HACK style comments
        match = _DEV_COMMENT_RE.search(line)
        if match:
            comment_text = match.group(0).strip()
            # Check if it contains sensitive keywords (higher severity)
            is_sensitive = any(kw in comment_text.lower() for kw in DEV_COMMENT_SENSITIVE_KEYWORDS)
            finding_id = hashlib.sha256(f"devcmt:{source_url}:{line_num}".encode()).hexdigest()[:16]
            findings.append({
                'id': finding_id,
                'type': 'dev_comment',
                'content': comment_text[:300],
                'source_url': source_url,
                'line': line_num,
                'severity': 'medium' if is_sensitive else 'info',
                'confidence': 'high' if is_sensitive else 'low',
            })
            continue

        # Check for comments with sensitive keywords
        sens_text = _sensitive_comment(line)
        if sens_text is not None:
            comment_text = sens_text.strip()
            # Avoid duplicating findings from the previous check
            if not _DEV_COMMENT_RE.search(line):
                finding_id = hashlib.sha256(f"senscmt:{source_url}:{line_num}".encode()).hexdigest()[:16]
                findings.append({
                    'id': finding_id,
                    'type': 'sensitive_comment',
                    'content': comment_text[:300],
                    'source_url': source_url,
                    'line': line_num,
                    'severity': 'medium',
                    'confidence': 'medium',
                })

    return findings


def load_custom_patterns(file_path: str) -> list:
    """
    Load custom patterns from a user-uploaded JSON or TXT file.

    JSON format: [{"name": "...", "regex": "...", "severity": "...", "confidence": "..."}]
    TXT format: name|regex|severity|confidence (one per line)

    Returns:
        List of pattern dicts ready to pass to scan_js_content(custom_patterns=...)
    """
    patterns = []
    if not file_path:
        return patterns

    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()

        if file_path.endswith('.json'):
            raw = json.loads(content)
            if isinstance(raw, list):
                patterns = raw
        else:
            # TXT format: name|regex|severity|confidence
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('|')
                if len(parts) >= 2:
                    patterns.append({
                        'name': parts[0].strip(),
                        'regex': parts[1].strip(),
                        'severity': parts[2].strip() if len(parts) > 2 else 'medium',
                        'confidence': parts[3].strip() if len(parts) > 3 else 'medium',
                        'category': 'custom',
                    })
    except Exception as e:
        print(f"[!][JsRecon] Failed to load custom patterns from {file_path}: {e}")

    return patterns
