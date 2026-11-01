#!/usr/bin/env python3
"""
RedAmon - GitHub Secret Hunter
====================================
Advanced reconnaissance tool for finding leaked secrets, credentials,
and sensitive data in GitHub repositories.

Features:
- 260+ regex patterns for common secrets (AWS, Azure, GCP, Stripe, AI/LLM, etc.)
- High-entropy string detection for unknown secret formats
- Commit history scanning to find deleted secrets
- Organization member and gist scanning
- Sensitive filename detection
- Rate limit handling with automatic retry
- JSON output for integration with other tools
"""

import re
import os
import json
import math
import time
from datetime import datetime, timezone
from typing import Optional, Dict, List, Set
from pathlib import Path

try:
    from github import Github, Auth
    from github.GithubException import RateLimitExceededException, GithubException
except ImportError:
    print("[!] PyGithub not installed. Run: pip install PyGithub")
    raise

# Every transport failure, not only ConnectionError/Timeout. PyGithub 2.x
# retries 5xx and rate-limited 403s itself (GithubRetry) and, once the retries
# run out, requests raises RetryError; a body cut off mid-read is
# ChunkedEncodingError. Neither is a GithubException, and both leave the file,
# commit or gist unread.
try:
    from requests.exceptions import RequestException as _RequestException
    _TRANSPORT_ERRORS = (_RequestException,)
except ImportError:
    _TRANSPORT_ERRORS = ()
try:
    from urllib3.exceptions import HTTPError as _Urllib3HTTPError
    _TRANSPORT_ERRORS += (_Urllib3HTTPError,)
except ImportError:
    pass

#: Gap records kept in the artifact. The count is always exact; the list is
#: capped so a run throttled for an hour does not write megabytes of them.
MAX_COVERAGE_GAP_RECORDS = 100

# Default settings for GitHub scanning (used when no settings provided)
DEFAULT_GITHUB_SETTINGS = {
    'GITHUB_ACCESS_TOKEN': os.getenv('GITHUB_ACCESS_TOKEN', ''),
    'GITHUB_TARGET_ORG': '',
    'GITHUB_TARGET_REPOS': '',
    'GITHUB_SCAN_MEMBERS': False,
    'GITHUB_SCAN_GISTS': True,
    'GITHUB_SCAN_COMMITS': True,
    'GITHUB_MAX_COMMITS': 100,
    'GITHUB_OUTPUT_JSON': True,
}

# =============================================================================
# SECRET PATTERNS - Comprehensive regex patterns for secret detection
# =============================================================================

SECRET_PATTERNS = {
    # ========== AWS ==========
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(?:_secret|_key|secret_key|_access).{0,10}['\"][0-9a-zA-Z/+]{40}['\"]",
    "AWS MWS Key": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",

    # ========== AZURE ==========
    "Azure Storage Key": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "Azure Connection String": r"(?i)(AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{40,}",
    "Azure SAS Token": r"(?i)[?&]sig=[A-Za-z0-9%]{40,}",
    "Azure AD Client Secret": r"(?i)(?:azure|msal|aad)[^\n]{0,120}?client.?secret[\"']?\s*[:=]\s*[\"'][a-zA-Z0-9~._-]{34,}[\"']",

    # ========== GOOGLE CLOUD ==========
    "GCP API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GCP OAuth Client": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "GCP Service Account": r"\"type\":\s*\"service_account\"",
    "Google OAuth Token": r"ya29\.[0-9A-Za-z\-_]+",
    "Google reCAPTCHA Key": r"6L[0-9A-Za-z-_]{38}",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase API Key": r"(?i)firebase[^\"']{0,50}['\"][A-Za-z0-9_]{30,}['\"]",
    "Firebase Storage": r"https://[a-z0-9-]+\.firebasestorage\.app",

    # ========== GITHUB ==========
    "GitHub Token (Classic)": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub Token (Fine-grained)": r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
    "GitHub OAuth": r"gho_[0-9a-zA-Z]{36}",
    "GitHub App Token": r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",
    "GitHub Refresh Token": r"ghr_[0-9a-zA-Z]{36}",
    "GitHub Credentials URL": r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com",

    # ========== GITLAB ==========
    "GitLab PAT": r"glpat-[0-9a-zA-Z\-_]{20}",
    "GitLab Runner Token": r"GR1348941[0-9a-zA-Z\-_]{20}",
    "GitLab Pipeline Token": r"glptt-[0-9a-zA-Z\-_]{20}",
    "GitLab Deploy Token": r"gldt-[0-9a-zA-Z\-_]{20}",
    "GitLab CICD Job Token": r"glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}",
    "GitLab Feed Token": r"glft-[0-9a-zA-Z\-_]{20}",
    "GitLab SCIM Token": r"glsoat-[0-9a-zA-Z\-_]{20}",
    "GitLab OAuth App Secret": r"gloas-[0-9a-f]{64}",

    # ========== SLACK ==========
    "Slack Bot Token": r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "Slack User Token": r"xoxp-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "Slack App Token": r"xapp-[0-9]{1,2}-[A-Z0-9]+-[0-9]+-[a-z0-9]+",
    "Slack Legacy Token": r"xox[os]-[0-9]{10,13}-[a-zA-Z0-9]{10,48}",
    "Slack Config Token": r"xoxe\.xox[bp]-[0-9]-[a-zA-Z0-9]{160,}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",

    # ========== STRIPE ==========
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24,}",
    "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24,}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24,}",

    # ========== PAYMENT PROCESSORS ==========
    "PayPal Client ID": r"(?i)paypal[^\n]{0,120}?client[_-]?id[^\n]{0,120}?['\"][A-Za-z0-9-]{20,}['\"]",
    "PayPal Braintree Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Razorpay Key": r"rzp_(live|test)_[a-zA-Z0-9]{14}",
    "Plaid Client ID": r"(?i)plaid[^\n]{0,120}?client.?id[^\n]{0,120}?['\"][a-f0-9]{24}['\"]",
    "Plaid Secret Key": r"(?i)plaid[^\n]{0,120}?secret[^\n]{0,120}?['\"][a-f0-9]{30}['\"]",
    "Plaid API Token": r"(?i)plaid[^\n]{0,120}?(?:access|public)[^\n]{0,120}?token[^\n]{0,120}?['\"][a-z0-9-]+['\"]",
    "Flutterwave Secret Key": r"FLWSECK-[a-zA-Z0-9]{32}-X",
    "Flutterwave Public Key": r"FLWPUBK-[a-zA-Z0-9]{32}-X",
    "Flutterwave Encryption Key": r"FLWSECK_TEST-[a-zA-Z0-9]{12}",
    "GoCardless API Token": r"(?i)gocardless[^\n]{0,120}?['\"]live_[a-zA-Z0-9\-_]{40,}['\"]",
    "Coinbase Access Token": r"(?i)coinbase[^\n]{0,120}?['\"][a-zA-Z0-9]{64}['\"]",

    # ========== CRYPTO EXCHANGES ==========
    "Kraken Access Token": r"(?i)kraken[^\n]{0,120}?['\"][a-zA-Z0-9/+]{40,}['\"]",
    "KuCoin Access Token": r"(?i)kucoin[^\n]{0,120}?['\"][a-f0-9]{24}['\"]",
    "KuCoin Secret Key": r"(?i)kucoin[^\n]{0,120}?secret[^\n]{0,120}?['\"][a-f0-9-]{36}['\"]",
    "Bittrex Access Key": r"(?i)bittrex[^\n]{0,120}?['\"][a-f0-9]{32}['\"]",
    "Bittrex Secret Key": r"(?i)bittrex[^\n]{0,120}?secret[^\n]{0,120}?['\"][a-f0-9]{32}['\"]",

    # ========== AI / LLM PROVIDERS ==========
    "OpenAI API Key": r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
    "OpenAI Project Key": r"sk-proj-[a-zA-Z0-9_-]{80,}",
    "Anthropic API Key": r"sk-ant-api03-[a-zA-Z0-9_\-]{93}AA",
    "Anthropic Admin Key": r"sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA",
    "HuggingFace Access Token": r"hf_[a-zA-Z]{34}",
    "HuggingFace Org Token": r"api_org_[a-zA-Z0-9]{34}",
    "Cohere API Token": r"(?i)cohere[^\n]{0,120}?['\"][a-zA-Z0-9]{40}['\"]",
    "Perplexity API Key": r"pplx-[a-f0-9]{48}",
    "Replicate API Token": r"r8_[a-zA-Z0-9]{40}",
    "Google Gemini API Key": r"(?i)gemini[^\n]{0,120}?['\"]AIza[0-9A-Za-z\-_]{35}['\"]",
    "Mistral API Key": r"(?i)mistral[^\n]{0,120}?['\"][a-zA-Z0-9]{32}['\"]",
    "Groq API Key": r"gsk_[a-zA-Z0-9]{52}",
    "Together AI Key": r"(?i)together[^\n]{0,120}?['\"][a-f0-9]{64}['\"]",
    "Deepseek API Key": r"(?i)deepseek[^\n]{0,120}?['\"]sk-[a-f0-9]{48}['\"]",

    # ========== SOCIAL MEDIA & APIs ==========
    "Twitter API Key": r"(?i)twitter[^\n]{0,120}?api[_-]?key[^\n]{0,120}?['\"][0-9a-zA-Z]{25}['\"]",
    "Twitter API Secret": r"(?i)twitter[^\n]{0,120}?api[_-]?secret[^\n]{0,120}?['\"][0-9a-zA-Z]{50}['\"]",
    "Twitter Access Token": r"(?i)twitter[^\n]{0,120}?access[_-]?token[^\n]{0,120}?['\"][0-9]+-[a-zA-Z0-9]{40,}['\"]",
    "Twitter Bearer Token": r"(?<![A-Za-z0-9+/=])AAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{30,}(?![A-Za-z0-9+/=])",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook Page Token": r"EAA[MC][a-zA-Z0-9]{100,}",
    "Facebook Secret": r"(?i)facebook[^\n]{0,120}?(?:secret|app.?secret)[^\n]{0,120}?['\"][a-f0-9]{32}['\"]",
    "Facebook OAuth": r"(?i)facebook[^\n]{0,120}?['\"][0-9]{13,17}['\"]",
    "LinkedIn Client ID": r"(?i)linkedin[^\n]{0,120}?client.?id[^\n]{0,120}?['\"][a-z0-9]{12,}['\"]",
    "LinkedIn Client Secret": r"(?i)linkedin[^\n]{0,120}?client.?secret[^\n]{0,120}?['\"][a-zA-Z0-9]{16}['\"]",
    "Twitch API Token": r"(?i)twitch[^\n]{0,120}?['\"][a-z0-9]{30}['\"]",

    # ========== MESSAGING ==========
    "Twilio API Key": r"\bSK[0-9a-fA-F]{32}\b",
    "Twilio Account SID": r"\bAC[a-zA-Z0-9]{32}\b",
    "Twilio App SID": r"\bAP[a-zA-Z0-9_\-]{32}\b",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9\-_]{43}",
    "Mailgun API Key": r"(?<![A-Za-z0-9])key-[0-9a-zA-Z]{32}",
    "Mailgun Public Key": r"pubkey-[a-f0-9]{32}",
    "Mailgun Signing Key": r"(?i)mailgun[^\n]{0,120}?signing[^\n]{0,120}?['\"][a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8}['\"]",
    "Mailchimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "SendinBlue API Key": r"xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}",
    "Telegram Bot Token": r"[0-9]+:AA[0-9A-Za-z\-_]{33}",
    "MessageBird API Token": r"(?i)messagebird[^\n]{0,120}?['\"][a-zA-Z0-9]{25}['\"]",
    "MessageBird Client ID": r"(?i)messagebird[^\n]{0,120}?client.?id[^\n]{0,120}?['\"][a-f0-9-]{36}['\"]",
    "Mattermost Access Token": r"(?i)mattermost[^\n]{0,120}?['\"][a-z0-9]{26}['\"]",
    "Microsoft Teams Webhook": r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+",

    # ========== DISCORD ==========
    "Discord Bot Token": r"[MN][A-Za-z\d]{23,}\.[\w-]{4,7}\.[\w-]{27,}",
    "Discord Client ID": r"(?i)discord[^\n]{0,120}?client.?id[^\n]{0,120}?['\"][0-9]{17,19}['\"]",
    "Discord Client Secret": r"(?i)discord[^\n]{0,120}?client.?secret[^\n]{0,120}?['\"][a-zA-Z0-9_-]{32}['\"]",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",

    # ========== DATABASES ==========
    "MongoDB Connection String": r"\bmongodb(?:\+srv)?://[^\s'\"]+",
    "PostgreSQL Connection String": r"\bpostgres(?:ql)?://[^\s'\"]+",
    "MySQL Connection String": r"\bmysql://[^\s'\"]+",
    "Redis URL": r"\bredis://[^\s'\"]+",
    "CockroachDB URL": r"\bcockroachdb://[^\s'\"]+",

    # ========== CI/CD & DEVOPS ==========
    "Heroku API Key": r"(?i)heroku[^\n]{0,120}?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Travis CI Token": r"(?i)travis[^\n]{0,120}?['\"][a-zA-Z0-9]{20,}['\"]",
    "CircleCI Token": r"(?i)circle[^\n]{0,120}?token[^\n]{0,120}?['\"][a-f0-9]{40}['\"]",
    "DroneCI Access Token": r"(?i)drone[^\n]{0,120}?['\"][a-zA-Z0-9]{32,}['\"]",
    "NPM Token": r"(?i)//registry\.npmjs\.org/:_authToken=[0-9a-f-]{36}",
    "PyPI Token": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}",
    "Docker Hub Token": r"dckr_pat_[A-Za-z0-9_-]{27}",
    "Clojars API Token": r"CLOJARS_[a-zA-Z0-9]{60}",
    "RubyGems API Token": r"rubygems_[a-f0-9]{48}",
    "NuGet API Key": r"oy2[a-z0-9]{43}",

    # ========== INFRASTRUCTURE / SECRET MANAGEMENT ==========
    "HashiCorp Vault Service Token": r"\bhvs\.[a-zA-Z0-9_-]{24,}\b",
    "HashiCorp Vault Batch Token": r"\bhvb\.[a-zA-Z0-9_-]{24,}\b",
    "HashiCorp Terraform Token": r"(?i)terraform[^\n]{0,120}?['\"][a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,}['\"]",
    "Doppler API Token": r"dp\.pt\.[a-zA-Z0-9]{43}",
    "Pulumi Access Token": r"pul-[a-f0-9]{40}",
    "Infracost API Token": r"ico-[a-zA-Z0-9]{32}",

    # ========== CLOUD & HOSTING ==========
    "DigitalOcean Token": r"dop_v1_[a-f0-9]{64}",
    "DigitalOcean OAuth": r"doo_v1_[a-f0-9]{64}",
    "DigitalOcean Refresh Token": r"dor_v1_[a-f0-9]{64}",
    "Cloudflare API Key": r"(?i)cloudflare[^\n]{0,120}?['\"][a-z0-9]{37}['\"]",
    "Cloudflare API Token": r"(?i)cloudflare[^\n]{0,120}?['\"][A-Za-z0-9_-]{40}['\"]",
    "Cloudflare Origin CA Key": r"v1\.0-[a-f0-9]{24}-[a-f0-9]{146}",
    "Cloudflare Global API Key": r"(?i)cloudflare[^\n]{0,120}?global[^\n]{0,120}?['\"][a-f0-9]{37}['\"]",
    "Netlify Access Token": r"nfp_[a-zA-Z0-9]{40}",
    "Fly.io Access Token": r"FlyV1\s+fm1r_[a-zA-Z0-9_-]{43}",
    "Vercel Token": r"(?i)vercel[^\n]{0,120}?['\"][a-zA-Z0-9]{24}['\"]",
    "Scalingo API Token": r"tk-us-[a-zA-Z0-9-_]{48}",
    "Render API Token": r"rnd_[a-zA-Z0-9]{32}",

    # ========== ALIBABA / YANDEX ==========
    "Alibaba Access Key ID": r"\bLTAI[a-zA-Z0-9]{20}\b",
    "Alibaba Secret Key": r"(?i)alibaba[^\n]{0,120}?['\"][a-z0-9]{30}['\"]",
    "Yandex API Key": r"(?i)yandex[^\n]{0,120}?['\"]AQVN[a-zA-Z0-9_\-]{35,38}['\"]",
    "Yandex Access Token": r"(?i)yandex[^\n]{0,120}?['\"]t1\.[A-Z0-9a-z_-]+={0,2}\.[A-Z0-9a-z_-]{86}={0,2}['\"]",
    "Yandex AWS Access Token": r"YC[a-zA-Z0-9_\-]{38}",

    # ========== E-COMMERCE ==========
    "Shopify Access Token": r"shpat_[a-fA-F0-9]{32}",
    "Shopify Custom Access Token": r"shpca_[a-fA-F0-9]{32}",
    "Shopify Private App Token": r"shppa_[a-fA-F0-9]{32}",
    "Shopify Shared Secret": r"shpss_[a-fA-F0-9]{32}",
    "Etsy Access Token": r"(?i)etsy[^\n]{0,120}?['\"][a-z0-9]{24}['\"]",
    "Squarespace Access Token": r"(?i)squarespace[^\n]{0,120}?['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]",

    # ========== OBSERVABILITY & MONITORING ==========
    "Datadog API Key": r"(?i)datadog[^\n]{0,120}?['\"][a-f0-9]{32}['\"]",
    "Datadog App Key": r"(?i)datadog[^\n]{0,120}?app[^\n]{0,120}?key[^\n]{0,120}?['\"][a-f0-9]{40}['\"]",
    "New Relic Insert Key": r"NRII-[A-Za-z0-9-_]{32}",
    "New Relic User API Key": r"NRAK-[A-Z0-9]{27}",
    "New Relic User API ID": r"(?i)new.?relic[^\n]{0,120}?['\"][0-9]{7}['\"]",
    "New Relic Browser API Token": r"NRJS-[a-f0-9]{19}",
    "Grafana API Key": r"eyJrIjoi[a-zA-Z0-9+/=]{60,}",
    "Grafana Cloud Token": r"glc_[A-Za-z0-9+/]{32,}={0,2}",
    "Grafana Service Account Token": r"glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}",
    "Sentry Access Token": r"sntrys_[a-zA-Z0-9]{56,}",
    "Sentry Org Token": r"sntryo_[a-zA-Z0-9]{56,}",
    "Sentry DSN": r"https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+",
    "Dynatrace API Token": r"dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}",
    "SumoLogic Access ID": r"(?i)sumo[^\n]{0,120}?access.?id[^\n]{0,120}?['\"]su[a-zA-Z0-9]{12}['\"]",
    "SumoLogic Access Token": r"(?i)sumo[^\n]{0,120}?access.?key[^\n]{0,120}?['\"][a-zA-Z0-9]{64}['\"]",

    # ========== DEV TOOLS & PROJECT MANAGEMENT ==========
    "Atlassian API Token": r"ATATT3[A-Za-z0-9_\-=]{186}",
    "Notion API Token": r"(?i)notion[^\n]{0,120}?secret_[a-zA-Z0-9]{43}",
    "Linear API Key": r"lin_api_[a-zA-Z0-9]{40}",
    "Linear Client Secret": r"(?i)linear[^\n]{0,120}?client.?secret[^\n]{0,120}?['\"][a-f0-9]{32}['\"]",
    "Asana Client ID": r"(?i)asana[^\n]{0,120}?['\"][0-9]{16}['\"]",
    "Asana Client Secret": r"(?i)asana[^\n]{0,120}?secret[^\n]{0,120}?['\"][a-z0-9]{32}['\"]",
    "Postman API Token": r"PMAK-[a-f0-9]{24}-[a-f0-9]{34}",
    "Bitbucket Client ID": r"(?i)bitbucket[^\n]{0,120}?client.?id[^\n]{0,120}?['\"][a-zA-Z0-9]{32}['\"]",
    "Bitbucket Client Secret": r"(?i)bitbucket[^\n]{0,120}?client.?secret[^\n]{0,120}?['\"][a-zA-Z0-9_\-]{64}['\"]",
    "Snyk API Token": r"(?i)snyk[^\n]{0,120}?['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]",
    "SonarQube Token": r"sqa_[a-zA-Z0-9]{40}",
    "Sourcegraph Access Token": r"sgp_[a-f0-9]{40}",
    "Codecov Access Token": r"codecov[^\n]{0,120}?['\"][a-f0-9]{32}['\"]",

    # ========== AUTH PROVIDERS ==========
    "Okta API Token": r"(?i)okta[^\n]{0,120}?['\"][0-9a-zA-Z_-]{42}['\"]",
    "Auth0 Client Secret": r"(?i)auth0[^\n]{0,120}?client.?secret[^\n]{0,120}?['\"][a-zA-Z0-9_-]{32,}['\"]",
    "HubSpot API Key": r"(?i)hubspot[^\n]{0,120}?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
    "Postmark Server Token": r"(?i)postmark[^\n]{0,120}?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
    "Intercom API Key": r"(?i)intercom[^\n]{0,120}?['\"][a-z0-9=_]{60}['\"]",

    # ========== INFRASTRUCTURE DISCOVERY ==========
    "Databricks API Token": r"dapi[a-h0-9]{32}",
    "Kubernetes Secret YAML": r"(?i)apiVersion:\s*v1\s*\nkind:\s*Secret",
    "Octopus Deploy API Key": r"API-[A-Z0-9]{25}",
    "OpenShift User Token": r"sha256~[a-zA-Z0-9_-]{43}",
    "Harness API Key": r"(?i)harness[^\n]{0,120}?pat\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}",

    # ========== JS-SPECIFIC SERVICES ==========
    "Algolia API Key": r"(?i)algolia[^\n]{0,120}?['\"][a-f0-9]{32}['\"]",
    "Algolia App ID": r"(?i)algolia[^\n]{0,120}?app.?id[^\n]{0,120}?['\"][A-Z0-9]{10}['\"]",
    "Mapbox Token": r"pk\.[a-zA-Z0-9]{60,}",
    "Pusher Key": r"(?i)pusher[^\n]{0,120}?key[^\n]{0,120}?['\"][a-f0-9]{20}['\"]",
    "Pusher Secret": r"(?i)pusher[^\n]{0,120}?secret[^\n]{0,120}?['\"][a-f0-9]{40}['\"]",
    "Segment Write Key": r"(?i)segment[^\n]{0,120}?write.?key[^\n]{0,120}?['\"][a-zA-Z0-9]{32}['\"]",
    "Amplitude API Key": r"(?i)amplitude[^\n]{0,120}?api.?key[^\n]{0,120}?['\"][a-f0-9]{32}['\"]",
    "LaunchDarkly SDK Key": r"(?i)sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "LaunchDarkly Access Token": r"(?i)api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "Contentful Token": r"(?i)contentful[^\n]{0,120}?['\"][a-zA-Z0-9_-]{43}['\"]",
    "Supabase Key": r"(?i)supabase[^\n]{0,120}?(?:anon|service)[^\n]{0,120}?key[^\n]{0,120}?eyJ[A-Za-z0-9-_]+",
    "PlanetScale Token": r"pscale_tkn_[a-zA-Z0-9_-]{43}",
    "PlanetScale OAuth Token": r"pscale_otkn_[a-zA-Z0-9_-]{43}",
    "PlanetScale Password": r"pscale_pw_[a-zA-Z0-9_-]{43}",
    "Next.js Env Leak": r"__NEXT_DATA__.{0,5000}(?:apiKey|secret|token|password)",

    # ========== MISC SAAS ==========
    "Dropbox API Token": r"(?i)dropbox[^\n]{0,120}?['\"]sl\.[a-zA-Z0-9\-_]{130,}['\"]",
    "Dropbox Short-lived Token": r"\bsl\.[A-Za-z0-9\-_]{130,}\b",
    "Freshbooks Access Token": r"(?i)freshbooks[^\n]{0,120}?['\"][a-f0-9]{64}['\"]",
    "Zendesk Secret Key": r"(?i)zendesk[^\n]{0,120}?['\"][a-zA-Z0-9]{40}['\"]",
    "Typeform API Token": r"tfp_[a-zA-Z0-9_-]{40,}",
    "Beamer API Token": r"(?i)beamer[^\n]{0,120}?b_[a-zA-Z0-9=_-]{44}",
    "ReadMe API Token": r"rdme_[a-z0-9]{70}",
    "Fastly API Token": r"(?i)fastly[^\n]{0,120}?['\"][a-zA-Z0-9_-]{32}['\"]",
    "Lob API Key": r"(?i)lob[^\n]{0,120}?(?:live|test)_[a-f0-9]{35}",
    "Lob Pub API Key": r"(?i)lob[^\n]{0,120}?(?:live|test)_pub_[a-f0-9]{31}",
    "Shippo API Token": r"shippo_(?:live|test)_[a-f0-9]{40}",
    "Duffel API Token": r"duffel_(?:live|test)_[a-zA-Z0-9_-]{43}",
    "EasyPost API Token": r"EZAK[a-f0-9]{54}",
    "EasyPost Test Token": r"EZTK[a-f0-9]{54}",
    "Finicity API Token": r"(?i)finicity[^\n]{0,120}?['\"][a-f0-9]{32}['\"]",
    "Frame.io API Token": r"fio-u-[a-zA-Z0-9\-_=]{64}",
    "Gitter Access Token": r"(?i)gitter[^\n]{0,120}?['\"][a-f0-9]{40}['\"]",
    "Airtable API Key": r"(?i)airtable[^\n]{0,120}?['\"][a-z0-9]{17}['\"]",
    "Airtable PAT": r"\bpat[a-zA-Z0-9]{14}\.[a-f0-9]{64}\b",
    "Adobe Client Secret": r"\bp8e-[a-zA-Z0-9]{32}\b",

    # ========== PASSWORD MANAGERS ==========
    "1Password Secret Key": r"\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b",
    "1Password Service Account Token": r"ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",

    # ========== SECURITY TOOLS ==========
    "Age Secret Key": r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
    "JFrog API Key": r"\bAKCp[A-Za-z0-9]{69}\b",
    "JFrog Reference Token": r"\bcmVmd[A-Za-z0-9]{59}\b",

    # ========== CRYPTOGRAPHIC KEYS ==========
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "DSA Private Key": r"-----BEGIN DSA PRIVATE KEY-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Generic Private Key": r"-----BEGIN PRIVATE KEY-----",
    "PKCS12 File": r"-----BEGIN CERTIFICATE-----",

    # ========== MODERN JS / SERVERLESS ECOSYSTEM ==========
    "Clerk Secret Key": r"sk_live_[a-zA-Z0-9]{27,}",
    "Clerk Publishable Key": r"pk_live_[a-zA-Z0-9]{27,}",
    "Clerk Test Secret Key": r"sk_test_[a-zA-Z0-9]{27,}",
    "Neon DB Connection String": r"\bpostgresql://[^\s'\"]*@[^\s'\"]*\.neon\.tech/[^\s'\"]+",
    "Upstash Redis REST Token": r"(?i)upstash[^\n]{0,120}?['\"]AX[a-zA-Z0-9_-]{36,}['\"]",
    "Resend API Key": r"re_[a-zA-Z0-9]{20,}",
    "Convex Deploy Key": r"(?:prod|dev):[a-z0-9]+:[a-zA-Z0-9_-]{40,}",
    "Turso DB Token": r"(?i)turso[^\n]{0,120}?eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "Trigger.dev API Key": r"tr_(?:dev|prod|test)_[a-zA-Z0-9]{24,}",
    "Axiom API Token": r"xaat-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "Axiom Ingest Token": r"xait-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "Pinecone API Key": r"pcsk_[a-zA-Z0-9_]{50,}",
    "Pinecone Legacy API Key": r"(?i)pinecone[^\n]{0,120}?['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]",
    "Weaviate API Key": r"(?i)weaviate[^\n]{0,120}?['\"][a-zA-Z0-9]{40,}['\"]",
    "Cloudinary URL": r"cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+",
    "Cloudinary API Secret": r"(?i)cloudinary[^\n]{0,120}?(?:api_?secret|secret)[^\n]{0,120}?['\"][a-zA-Z0-9_-]{27}['\"]",
    "WorkOS API Key": r"sk_(?:live|test)_[a-zA-Z0-9]{30,}",
    "Liveblocks Secret Key": r"sk_(?:prod|dev)_[a-zA-Z0-9_-]{30,}",
    "Sanity Project Token": r"sk[a-zA-Z0-9]{8,}\.(?:production|dataset)\.[a-zA-Z0-9]+",
    "Expo Access Token": r"expo_[a-zA-Z0-9]{40,}",
    "Sentry Auth Token (new)": r"sntrys_eyJ[a-zA-Z0-9+/=_-]{80,}",

    # ========== JWT & AUTH ==========
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Basic Auth Header": r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]+",
    "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",

    # ========== GENERIC PATTERNS ==========
    "Generic API Key": r"(?i)(api[_-]?key|apikey|api_secret)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?",
    "Generic Secret": r"(?i)(secret|password|passwd|pwd)[\"']?\s*[:=]\s*[\"'][^\"']{8,}[\"']",
    "Generic Token": r"(?i)(access[_-]?token|auth[_-]?token)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?",
    "Hardcoded Password": r"(?i)(password|passwd|pwd)\s*=\s*[\"'][^\"']{4,}[\"']",

    # ========== INFRASTRUCTURE URLS ==========
    "S3 Bucket (path-style)": r"https?://s3(?:[.-][\w-]+)?\.amazonaws\.com/([a-zA-Z0-9._-]+)",
    "S3 Bucket (virtual-hosted)": r"https?://([a-zA-Z0-9._-]+)\.s3(?:[.-][\w-]+)?\.amazonaws\.com",
    "S3 ARN": r"arn:aws:s3:::([a-zA-Z0-9._-]+)",
    "GCP Storage": r"https?://storage\.googleapis\.com/([a-zA-Z0-9._-]+)",
    "GCP gs:// URL": r"gs://([a-zA-Z0-9._-]+)",
    "Azure Blob Storage": r"https?://([a-zA-Z0-9]+)\.blob\.core\.windows\.net",
    "IP Address (Private)": r"(?:^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})(?:[^0-9]|$)",
}

def redact_sample(text: str) -> str:
    """The stored form of a matched value: its first and last characters, as
    js_recon's `redacted_value` (recon/helpers/js_recon/patterns.py `redact`).
    Idempotent, so the graph writer can apply it again to an older artifact."""
    if len(text) > 12:
        return text[:6] + '...' + text[-4:]
    if len(text) > 4:
        return text[:3] + '...'
    return '***'


# Two checks mirrored from js_recon (recon/helpers/js_recon/patterns.py,
# `_has_key_data` and `_REQUIRES_NEARBY`), the hunter's own copy as its
# patterns are: a private-key marker counts only with key data after it (in
# code it opens a parser branch or a template), and `YC` + 38 counts only
# with "yandex" before it (it is also a webpack chunk id).
_PEM_KEY_TYPES = frozenset({
    "RSA Private Key", "DSA Private Key", "EC Private Key", "OpenSSH Private Key",
    "PGP Private Key", "Generic Private Key",
})
_PEM_MIN_KEY_CHARS = 64
_PEM_LOOKAHEAD = 4000
_PEM_EDGE_CHARS = ' \t"\'`+,;()'
_PEM_ARMOR_HEADER = re.compile(r'^[A-Za-z][A-Za-z-]*:\s')
_BASE64_RUN = re.compile(r'[A-Za-z0-9+/=]+')
_REQUIRES_NEARBY = {
    "Yandex AWS Access Token": (re.compile(r'(?i)yandex'), 120),
}


def _has_key_data(after: str) -> bool:
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


def _reportable(secret_type: str, content: str, match) -> bool:
    if secret_type in _PEM_KEY_TYPES:
        return _has_key_data(content[match.end():match.end() + _PEM_LOOKAHEAD])
    nearby = _REQUIRES_NEARBY.get(secret_type)
    if nearby:
        keyword, reach = nearby
        return bool(keyword.search(content[max(0, match.start() - reach):match.start()]))
    return True


# Pre-compile all patterns at module load time for performance
COMPILED_SECRET_PATTERNS = {}
for _name, _regex in SECRET_PATTERNS.items():
    try:
        COMPILED_SECRET_PATTERNS[_name] = re.compile(_regex)
    except re.error:
        print(f"[!] Failed to compile pattern: {_name}")

# Sensitive filenames to flag
SENSITIVE_FILENAMES = {
    # Credentials & Keys
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    ".env.backup", ".env.old", ".env.example", "credentials", "credentials.json",
    "id_rsa", "id_rsa.pub", "id_dsa", "id_ecdsa", "id_ed25519",
    ".pem", ".key", ".p12", ".pfx", ".asc",

    # Config files
    "config.json", "config.yaml", "config.yml", "secrets.json", "secrets.yaml",
    "settings.json", "settings.yaml", "application.properties", "application.yml",
    ".htpasswd", ".netrc", ".npmrc", ".pypirc", ".dockercfg",
    "docker-compose.override.yml", "wp-config.php", "database.yml",

    # Cloud configs
    "terraform.tfvars", "terraform.tfstate", "*.auto.tfvars",
    "ansible-vault", "vault.yml", "secrets.enc",

    # History & Backups
    ".bash_history", ".zsh_history", ".mysql_history", ".psql_history",
    "backup.sql", "dump.sql", "database.sql",

    # AWS
    ".aws/credentials", "aws_credentials", ".s3cfg",

    # GCP
    "service-account.json", "gcp-credentials.json",

    # Kubernetes
    "kubeconfig", ".kube/config",
}

# File extensions to skip (binary/large files)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".min.js", ".min.css",  # Minified files
    ".map",  # Source maps
    ".lock",  # Lock files
}

# =============================================================================
# ENTROPY DETECTION - Find high-entropy strings (potential secrets)
# =============================================================================

def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0

    entropy = 0.0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def find_high_entropy_strings(content: str, threshold: float = 4.5) -> List[Dict]:
    """Find high-entropy strings that might be secrets."""
    findings = []

    # Look for quoted strings and assignments
    patterns = [
        r'["\']([A-Za-z0-9+/=_-]{20,})["\']',  # Quoted strings
        r'=\s*([A-Za-z0-9+/=_-]{20,})',  # Assignments
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, content):
            candidate = match.group(1)
            entropy = calculate_shannon_entropy(candidate)

            if entropy >= threshold and len(candidate) >= 20:
                # Skip if it looks like a common word or path
                if not re.match(r'^[a-z]+$', candidate, re.I):
                    findings.append({
                        "type": "High Entropy String",
                        "value": candidate[:50] + "..." if len(candidate) > 50 else candidate,
                        "entropy": round(entropy, 2),
                        "length": len(candidate)
                    })

    return findings

# =============================================================================
# GITHUB SECRET HUNTER CLASS
# =============================================================================

class GitHubSecretHunter:
    """Advanced GitHub secret scanning tool."""

    #: What this run could not scan because GitHub throttled or failed, as
    #: opposed to content that is simply unreadable (a submodule entry). A run
    #: with any is incomplete, and the graph write will not prune on it.
    #: Rebound rather than mutated, so these class defaults are never shared.
    coverage_gap_count = 0
    coverage_gaps: tuple = ()

    def __init__(self, token: str, target: str, project_id: str = "", settings: Optional[Dict] = None):
        self.token = token
        self.target = target
        self.project_id = project_id
        self.auth = Auth.Token(token)
        self.github = Github(auth=self.auth)

        # Store settings (use defaults if not provided)
        self.settings = settings or DEFAULT_GITHUB_SETTINGS

        # Parse target repos filter (comma-separated → set of lowercase names)
        repos_str = self.settings.get('GITHUB_TARGET_REPOS', '')
        self.target_repos = {r.strip().lower() for r in repos_str.split(',') if r.strip()} if repos_str else set()

        self.findings: List[Dict] = []
        self.scanned_repos: Set[str] = set()
        self.stats = {
            "repos_scanned": 0,
            "files_scanned": 0,
            "commits_scanned": 0,
            "gists_scanned": 0,
            "secrets_found": 0,
            "sensitive_files": 0,
            "high_entropy": 0,
        }

        # Rate limit tracking
        self.rate_limit_hits = 0

        # Initialize output file for incremental saving
        self.output_dir = Path(__file__).parent / "output"
        self.output_dir.mkdir(exist_ok=True)

        # Create output filename using project_id for consistency with other modules
        self.scan_start_time = datetime.now()
        if project_id:
            self.output_file = self.output_dir / f"github_hunt_{project_id}.json"
        else:
            self.output_file = self.output_dir / f"github_secrets_{target}.json"

        # Initialize the JSON file immediately
        self._init_output_file()

    def _init_output_file(self):
        """Initialize the JSON output file at scan start."""
        if not self.settings.get('GITHUB_OUTPUT_JSON', True):
            return

        initial_data = {
            "target": self.target,
            "scan_start_time": self.scan_start_time.isoformat(),
            "scan_end_time": None,
            "status": "in_progress",
            "statistics": self.stats,
            "findings": []
        }

        with open(self.output_file, 'w') as f:
            json.dump(initial_data, f, indent=2)

        print(f"[*] Output file initialized: {self.output_file}")

    def _save_incremental(self):
        """Save current state to JSON file (called after each finding)."""
        if not self.settings.get('GITHUB_OUTPUT_JSON', True):
            return

        data = {
            "target": self.target,
            "scan_start_time": self.scan_start_time.isoformat(),
            "scan_end_time": None,
            "status": "in_progress",
            "last_update": datetime.now().isoformat(),
            "statistics": self.stats,
            **self._coverage_fields(),
            "findings": self.findings
        }

        # Write to temp file first, then rename (atomic operation)
        temp_file = self.output_file.with_suffix('.tmp')
        try:
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
            temp_file.replace(self.output_file)
        except Exception as e:
            print(f"    [!] Error saving incremental: {e}")
            # Fallback: write directly
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(data, f, indent=2)
            except:
                pass

    def _handle_rate_limit(self):
        """Handle GitHub rate limit with exponential backoff."""
        self.rate_limit_hits += 1
        # Save before waiting (in case user cancels)
        self._save_incremental()

        rate_limit = self.github.get_rate_limit()
        reset_time = rate_limit.core.reset
        # PyGithub >= 2.0 returns an AWARE datetime; subtracting a naive
        # utcnow() raises TypeError from inside the rate-limit handler and
        # aborts the whole scan, skipping the graph write. Match the tzinfo of
        # whatever this PyGithub hands back.
        now = datetime.now(timezone.utc) if reset_time.tzinfo else datetime.utcnow()
        wait_seconds = (reset_time - now).total_seconds() + 10

        if wait_seconds > 0:
            print(f"\n[!] Rate limit hit! Waiting {int(wait_seconds)} seconds...")
            print(f"    Reset time: {reset_time}")
            time.sleep(min(wait_seconds, 300))  # Max 5 min wait
        else:
            time.sleep(60)  # Default wait

    @staticmethod
    def _is_rate_limit(error: BaseException) -> bool:
        """A primary or secondary rate limit, however PyGithub surfaced it.

        RateLimitExceededException is itself a GithubException with status 403,
        so a handler testing only the status reads a throttled request as
        "forbidden". Older PyGithub releases also raise a plain GithubException
        for some throttles, which only the headers or the message give away.
        """
        if isinstance(error, RateLimitExceededException):
            return True
        if not isinstance(error, GithubException):
            return False
        status = getattr(error, "status", None)
        if status == 429:
            return True
        if status != 403:
            return False
        headers = getattr(error, "headers", None) or {}
        try:
            remaining = next((str(v) for k, v in headers.items()
                              if str(k).lower() == "x-ratelimit-remaining"), None)
        except AttributeError:
            remaining = None
        if remaining == "0":
            return True
        data = getattr(error, "data", None)
        message = data.get("message") if isinstance(data, dict) else None
        message = str(message or getattr(error, "message", None) or "").lower()
        return "rate limit" in message or "abuse" in message

    def _loses_coverage(self, error: BaseException) -> bool:
        """Whether `error` left content unscanned that a later run would read.

        Deliberately narrow: a submodule entry, a symlink or an empty
        repository fails the same way on every run, and counting those would
        mark every such project's hunts incomplete for ever.
        """
        if self._is_rate_limit(error):
            return True
        if isinstance(error, GithubException):
            status = getattr(error, "status", None)
            return isinstance(status, int) and status >= 500
        return bool(_TRANSPORT_ERRORS) and isinstance(error, _TRANSPORT_ERRORS)

    def _record_gap(self, kind: str, where: str, error: BaseException):
        """Note something this run did not scan, so the graph write keeps the
        findings it would otherwise have pruned as gone."""
        reason = type(error).__name__
        status = getattr(error, "status", None)
        if status:
            reason = f"{reason} {status}"
        self.coverage_gap_count += 1
        if len(self.coverage_gaps) < MAX_COVERAGE_GAP_RECORDS:
            self.coverage_gaps = [*self.coverage_gaps,
                                  {"kind": kind, "where": where, "reason": reason}]
        print(f"    [!] Not scanned ({kind}): {where} - {reason}")

    def _coverage_fields(self) -> Dict:
        """The artifact's gap keys, present only on a run that had gaps, so a
        clean run's JSON keeps exactly the shape it always had."""
        if not self.coverage_gap_count:
            return {}
        return {"coverage_gap_count": self.coverage_gap_count,
                "coverage_gaps": list(self.coverage_gaps)}

    @staticmethod
    def _is_public(private) -> Optional[bool]:
        """Visibility from the listing payload's `private`, or None if unknown.

        Read from the object the listing already returned: no extra API call.
        """
        return (not private) if isinstance(private, bool) else None

    def _should_skip_file(self, filename: str) -> bool:
        """Check if file should be skipped based on extension."""
        ext = os.path.splitext(filename)[1].lower()
        return ext in SKIP_EXTENSIONS

    def _is_sensitive_filename(self, filepath: str) -> bool:
        """Check if filename is in sensitive list."""
        filename = os.path.basename(filepath).lower()
        return filename in SENSITIVE_FILENAMES or any(
            sens.lower() in filepath.lower() for sens in SENSITIVE_FILENAMES
        )

    def _add_finding(self, finding_type: str, repo: str, path: str,
                     secret_type: str, details: Optional[Dict] = None,
                     repository_public: Optional[bool] = None):
        """Add a finding to the results and save incrementally."""
        finding = {
            "timestamp": datetime.now().isoformat(),
            "type": finding_type,
            "repository": repo,
            "path": path,
            "secret_type": secret_type,
            "details": details or {}
        }
        # Only when known: triage reads a public repository as fully reachable,
        # and an absent key is "unknown", which a guessed false would erase.
        if isinstance(repository_public, bool):
            finding["repository_public"] = repository_public
        self.findings.append(finding)

        # Color-coded output
        if finding_type == "SECRET":
            print(f"\033[91m[!!!] SECRET FOUND: {secret_type}\033[0m")
            self.stats["secrets_found"] += 1
        elif finding_type == "SENSITIVE_FILE":
            print(f"\033[93m[!] SENSITIVE FILE: {path}\033[0m")
            self.stats["sensitive_files"] += 1
        elif finding_type == "HIGH_ENTROPY":
            print(f"\033[95m[~] HIGH ENTROPY: {secret_type}\033[0m")
            self.stats["high_entropy"] += 1

        print(f"    Repository: {repo}")
        print(f"    Path: {path}")
        if details:
            # I4: never print the cleartext secret to stdout (docker logs / operator
            # log stream). Redact the value-bearing fields; keep non-sensitive
            # metadata. The on-disk JSON artifact keeps the value (tracker decision).
            _SENSITIVE_KEYS = {"sample", "value", "secret", "match", "matched",
                               "raw", "token", "entropy_value", "high_entropy_value"}
            for key, value in details.items():
                if key.lower() in _SENSITIVE_KEYS:
                    print(f"    {key}: [REDACTED]")
                else:
                    print(f"    {key}: {value}")
        print()

        # Save incrementally after each finding
        self._save_incremental()

    def scan_file_content(self, repo_name: str, content: str, path: str,
                          repository_public: Optional[bool] = None):
        """Scan file content for secrets using regex patterns."""
        for secret_type, compiled_re in COMPILED_SECRET_PATTERNS.items():
            # The whole match, as js_recon stores it: `findall` returns a
            # pattern's capturing group, which for the generic ones is the
            # keyword ("password"), not the value.
            matches = [m.group(0) for m in compiled_re.finditer(content)
                       if _reportable(secret_type, content, m)]
            if matches:
                self._add_finding(
                    "SECRET", repo_name, path, secret_type,
                    # `value` stays in the on-disk artifact only (stdout prints
                    # it [REDACTED]); the graph gets the redacted `sample`.
                    {"matches": len(matches), "sample": redact_sample(matches[0]),
                     "value": matches[0][:100]},
                    repository_public=repository_public,
                )

        # Entropy-based detection
        high_entropy = find_high_entropy_strings(content)
        for finding in high_entropy[:5]:  # Limit to top 5 per file
            self._add_finding(
                "HIGH_ENTROPY", repo_name, path,
                f"High Entropy ({finding['entropy']})",
                finding,
                repository_public=repository_public,
            )

    def scan_repo_contents(self, repo, path: str = ""):
        """Recursively scan repository contents."""
        public = self._is_public(getattr(repo, "private", None))
        try:
            contents = repo.get_contents(path)
            if not isinstance(contents, list):
                contents = [contents]

            for item in contents:
                if item.type == "dir":
                    self.scan_repo_contents(repo, item.path)
                else:
                    # Check sensitive filename
                    if self._is_sensitive_filename(item.path):
                        self._add_finding(
                            "SENSITIVE_FILE", repo.full_name, item.path,
                            "Sensitive Filename",
                            repository_public=public,
                        )

                    # Skip binary/large files
                    if self._should_skip_file(item.name):
                        continue

                    # Scan file content
                    try:
                        if item.size < 500000:  # Skip files > 500KB
                            decoded = item.decoded_content.decode('utf-8', errors='ignore')
                            self.scan_file_content(repo.full_name, decoded, item.path,
                                                   repository_public=public)
                            self.stats["files_scanned"] += 1
                            # Save every 50 files to track progress
                            if self.stats["files_scanned"] % 50 == 0:
                                self._save_incremental()
                    except Exception as e:
                        if self._loses_coverage(e):
                            self._record_gap("file", f"{repo.full_name}:{item.path}", e)
                        continue

        except RateLimitExceededException:
            self._handle_rate_limit()
            self.scan_repo_contents(repo, path)
        except GithubException as e:
            if e.status != 404:  # Ignore not found (empty repos)
                print(f"    [!] Error accessing {path}: {e}")
                if self._loses_coverage(e):
                    self._record_gap("directory", f"{repo.full_name}:{path or '/'}", e)

    def scan_commit_history(self, repo):
        """Scan commit history for leaked secrets."""
        if not self.settings.get('GITHUB_SCAN_COMMITS', True):
            return

        public = self._is_public(getattr(repo, "private", None))
        try:
            commits = repo.get_commits()
            count = 0
            max_commits_setting = self.settings.get('GITHUB_MAX_COMMITS', 100)
            max_commits = max_commits_setting if max_commits_setting > 0 else float('inf')

            for commit in commits:
                if count >= max_commits:
                    break

                try:
                    for file in commit.files:
                        if file.patch and not self._should_skip_file(file.filename):
                            self.scan_file_content(
                                repo.full_name,
                                file.patch,
                                f"{file.filename} (commit: {commit.sha[:7]})",
                                repository_public=public,
                            )
                    self.stats["commits_scanned"] += 1
                    count += 1
                    # Save every 20 commits to track progress
                    if count % 20 == 0:
                        self._save_incremental()
                except Exception as e:
                    if self._loses_coverage(e):
                        sha = str(getattr(commit, "sha", "") or "")[:7]
                        self._record_gap("commit", f"{repo.full_name}@{sha}", e)
                    continue

        except RateLimitExceededException as e:
            self._handle_rate_limit()
            self._record_gap("commits", repo.full_name, e)
        except Exception as e:
            print(f"    [!] Error scanning commits: {e}")
            if self._loses_coverage(e):
                self._record_gap("commits", repo.full_name, e)

    def scan_repo(self, repo):
        """Scan a single repository."""
        # Filter by target repos if specified
        if self.target_repos and repo.name.lower() not in self.target_repos:
            return

        if repo.full_name in self.scanned_repos:
            return

        self.scanned_repos.add(repo.full_name)
        print(f"\n[*] Scanning repository: {repo.full_name}")
        print(f"    Stars: {repo.stargazers_count} | Forks: {repo.forks_count}")

        # 1. Recursive content scan (thorough)
        self.scan_repo_contents(repo)

        # 2. Commit history scan (optional, slow)
        if self.settings.get('GITHUB_SCAN_COMMITS', True):
            self.scan_commit_history(repo)

        self.stats["repos_scanned"] += 1

        # Save after each repo is completed
        self._save_incremental()
        print(f"    [✓] Repo scan complete. Progress saved.")

    def scan_gists(self, user):
        """Scan user gists for secrets."""
        if not self.settings.get('GITHUB_SCAN_GISTS', True):
            return

        try:
            for gist in user.get_gists():
                print(f"    [*] Scanning gist: {gist.id}")
                public = getattr(gist, "public", None)
                public = public if isinstance(public, bool) else None
                for filename, file in gist.files.items():
                    if not self._should_skip_file(filename):
                        try:
                            content = file.content
                            self.scan_file_content(
                                f"gist:{user.login}",
                                content,
                                f"{gist.id}/{filename}",
                                repository_public=public,
                            )
                            self.stats["gists_scanned"] += 1
                        except Exception as e:
                            if self._loses_coverage(e):
                                self._record_gap("gist", f"{gist.id}/{filename}", e)
                            continue

        except RateLimitExceededException as e:
            self._handle_rate_limit()
            self._record_gap("gists", f"gist:{user.login}", e)
        except Exception as e:
            print(f"    [!] Error scanning gists: {e}")
            if self._loses_coverage(e):
                self._record_gap("gists", f"gist:{user.login}", e)

    def scan_organization(self):
        """Scan an organization and its members."""
        org = None
        try:
            org = self.github.get_organization(self.target)
            print(f"\n[*] Organization found: {org.login}")
            print(f"    Public repos: {org.public_repos}")
            print(f"    Members: {org.get_members().totalCount if org.get_members() else 'N/A'}")

            # Scan organization repos
            for repo in org.get_repos():
                self.scan_repo(repo)

            # Scan member repos and gists
            if self.settings.get('GITHUB_SCAN_MEMBERS', False):
                print("\n[*] Scanning organization members...")
                for member in org.get_members():
                    print(f"\n[*] Member: {member.login}")

                    for repo in member.get_repos():
                        self.scan_repo(repo)

                    if self.settings.get('GITHUB_SCAN_GISTS', True):
                        self.scan_gists(member)

        except GithubException as e:
            # A throttled request is also a 403. Read as "not an organisation"
            # it rescanned the target as a user and dropped the org's members.
            if self._is_rate_limit(e):
                if org is None:
                    raise  # nothing scanned yet: run()'s wait-and-retry is cheap
                # Part-way through: run() would restart every repo from the top.
                self._record_gap("organization", self.target, e)
                return
            if e.status in (404, 403):
                if org is not None:
                    # The org resolved, so this failed part-way through it and
                    # whatever was left of it is not rescanned below.
                    self._record_gap("organization", self.target, e)
                # Not an organization (404) or no org access (403) — try as a user
                self.scan_user()
            else:
                raise

    def scan_user(self):
        """Scan a user's repositories and gists."""
        user = None
        try:
            user = self.github.get_user(self.target)
            print(f"\n[*] User found: {user.login}")
            print(f"    Public repos: {user.public_repos}")

            for repo in user.get_repos():
                self.scan_repo(repo)

            if self.settings.get('GITHUB_SCAN_GISTS', True):
                print("\n[*] Scanning user gists...")
                self.scan_gists(user)

        except GithubException as e:
            if self._is_rate_limit(e) and user is None:
                raise  # nothing scanned yet: run()'s wait-and-retry is cheap
            print(f"[!] Error: {e}")
            # Every repo and gist after the failure point went unscanned.
            self._record_gap("target", self.target, e)

    def save_results(self, status: str = "completed"):
        """Save final results to JSON file."""
        if not self.settings.get('GITHUB_OUTPUT_JSON', True):
            return

        scan_end_time = datetime.now()
        duration = (scan_end_time - self.scan_start_time).total_seconds()

        results = {
            "target": self.target,
            "scan_start_time": self.scan_start_time.isoformat(),
            "scan_end_time": scan_end_time.isoformat(),
            "duration_seconds": round(duration, 2),
            "status": status,
            "last_update": scan_end_time.isoformat(),
            "statistics": self.stats,
            **self._coverage_fields(),
            "findings": self.findings
        }

        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n[*] Final results saved to: {self.output_file}")

    def print_summary(self):
        """Print scan summary."""
        print("\n" + "=" * 70)
        print("                         SCAN SUMMARY")
        print("=" * 70)
        print(f"  Target:              {self.target}")
        print(f"  Repos Scanned:       {self.stats['repos_scanned']}")
        print(f"  Files Scanned:       {self.stats['files_scanned']}")
        print(f"  Commits Scanned:     {self.stats['commits_scanned']}")
        print(f"  Gists Scanned:       {self.stats['gists_scanned']}")
        print("-" * 70)
        print(f"\033[91m  Secrets Found:       {self.stats['secrets_found']}\033[0m")
        print(f"\033[93m  Sensitive Files:     {self.stats['sensitive_files']}\033[0m")
        print(f"\033[95m  High Entropy:        {self.stats['high_entropy']}\033[0m")
        print(f"  Rate Limit Hits:     {self.rate_limit_hits}")
        if self.coverage_gap_count:
            print(f"  Not Scanned:         {self.coverage_gap_count} "
                  f"(throttled or failed; old findings are kept, not pruned)")
        print("=" * 70)

        if self.stats['secrets_found'] > 0:
            print("\n\033[91m[!!!] CRITICAL: Secrets were found! Review findings immediately.\033[0m")

    def run(self):
        """Run the complete scan."""
        status = "completed"

        try:
            # Check if target is org or user
            self.scan_organization()
        except KeyboardInterrupt:
            print("\n\n[!] Scan interrupted by user.")
            status = "interrupted"
        except Exception as e:
            # Not only RateLimitExceededException: PyGithub 2.x raises a 429 as
            # a plain GithubException, which _is_rate_limit recognises.
            if self._is_rate_limit(e):
                self._handle_rate_limit()
                self.run()
                return self.findings
            print(f"[!] Error during scan: {e}")
            status = "error"

        self.print_summary()
        self.save_results(status)

        return self.findings
