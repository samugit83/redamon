"""
JS Recon Key Validators

Live API validation for discovered secrets/keys. Each validator makes a single
API call to confirm if a key is active and returns scope/permission info.

Rate-limited: 1 req/sec per service via threading.Lock.

Every validator stays alongside JS Recon's TruffleHog engine (plan step 2.5):
TruffleHog cannot say a key is dead (with no network its checks answer "not
verified" exactly as for a dead key), so these validators remain the only
source of `rejected`; `validate_firebase` (an open database read) and
`validate_google_maps` (the key's API restriction) test what a key opens, not
whether it lives. A key TruffleHog verified skips its provider call here,
except for those two (js_recon._validate_secrets).
"""

import re
import math
import time
import threading
import requests
from typing import Optional


# Per-service rate limiting locks
_service_locks = {}
_lock_creation_lock = threading.Lock()


def _get_service_lock(service: str) -> threading.Lock:
    """Get or create a per-service lock for rate limiting."""
    with _lock_creation_lock:
        if service not in _service_locks:
            _service_locks[service] = threading.Lock()
        return _service_locks[service]


#: What a validator learned about a credential. `valid` and `rejected` are the
#: provider's verdict; `unknown` is no verdict (timeout, 429, 5xx, a network
#: error, a breaker skip, a 403); `format_invalid` needs no call.
VALID = 'valid'
REJECTED = 'rejected'
UNKNOWN = 'unknown'
FORMAT_INVALID = 'format_invalid'


def _result(state: str, *, scope: str = '', info: str = '', error: str = '') -> dict:
    return {'valid': state == VALID, 'state': state, 'scope': scope, 'info': info, 'error': error}


def _no_answer(resp) -> dict:
    """A non-2xx answer. Only a 401 says the provider does not accept the
    credential; a 403 is as often a live key missing a scope or an SSO grant,
    a 404 a moved endpoint, a 429 or 5xx the service itself, so they are no
    verdict: hiding a live credential is the failure to avoid."""
    return _result(REJECTED if resp.status_code == 401 else UNKNOWN,
                   info=f"status={resp.status_code}")


def _skipped_result(detail: str) -> dict:
    return _result(UNKNOWN, error=f'skipped ({detail})')


def _rate_limited_request(service: str, func, timeout: int = 5):
    """Execute a request with per-service rate limiting (1 req/sec).

    Each service has its own breaker: after a few unreachable calls in a row
    the rest are skipped (a validator serialises at 1 req/s, so a dead service
    otherwise costs 5s + 1s for every discovered key of that kind). A skip
    returns the same shape a real failure returns, so js_recon is unchanged. A
    key that is simply invalid is an HTTP answer, never a breaker failure.
    """
    from recon.helpers import circuit_breaker as cb
    breaker = cb.get_breaker(f"secretval:{service}", label="SecretValidator",
                             threshold=cb.INTERNAL_THRESHOLD)
    if not breaker.allow():
        return _skipped_result(breaker.detail)
    lock = _get_service_lock(service)
    with lock:
        epoch = breaker.epoch()
        try:
            result = func(timeout)
            breaker.record(cb.Outcome.OK, epoch=epoch)
            time.sleep(1)  # 1 req/sec per service
            return result
        except requests.Timeout:
            breaker.record(cb.Outcome.TRANSIENT, "Timeout", epoch=epoch)
            return _result(UNKNOWN, error='timeout')
        except requests.RequestException as e:
            breaker.record(cb.Outcome.TRANSIENT, type(e).__name__, epoch=epoch)
            return _result(UNKNOWN, error=type(e).__name__)
        except Exception as e:
            breaker.record(cb.Outcome.TRANSIENT, type(e).__name__, epoch=epoch)
            return _result(UNKNOWN, error=type(e).__name__)


def validate_aws(matched_text: str, timeout: int = 5) -> dict:
    """Validate AWS Access Key via sts:GetCallerIdentity (requires both key ID and secret)."""
    # AWS validation requires both access key ID and secret key
    # We can only validate if both are available in the matched context
    key_match = re.search(r'(AKIA[0-9A-Z]{16})', matched_text)
    if not key_match:
        return _result(UNKNOWN, info='Could not extract key ID', error='no_key_found')

    return _result(UNKNOWN, info='AWS validation requires secret key pair', error='incomplete_credentials')


def validate_github(matched_text: str, timeout: int = 5) -> dict:
    """Validate GitHub token via GET /user."""
    token = re.search(r'(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}|gho_[0-9a-zA-Z]{36}|(?:ghu|ghs)_[0-9a-zA-Z]{36})', matched_text)
    if not token:
        return _result(UNKNOWN, error='no_token_found')

    def do_request(t):
        resp = requests.get('https://api.github.com/user',
                          headers={'Authorization': f'token {token.group(1)}', 'User-Agent': 'RedAmon-JsRecon'},
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            scopes = resp.headers.get('X-OAuth-Scopes', 'unknown')
            return _result(VALID, scope=scopes, info=f"user={data.get('login')}")
        return _no_answer(resp)

    return _rate_limited_request('github', do_request, timeout)


def validate_gitlab(matched_text: str, timeout: int = 5) -> dict:
    """Validate GitLab token via GET /api/v4/user."""
    token = re.search(r'(glpat-[0-9a-zA-Z\-_]{20})', matched_text)
    if not token:
        return _result(UNKNOWN, error='no_token_found')

    def do_request(t):
        resp = requests.get('https://gitlab.com/api/v4/user',
                          headers={'PRIVATE-TOKEN': token.group(1)},
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            return _result(VALID, scope='api', info=f"user={data.get('username')}, admin={data.get('is_admin')}")
        return _no_answer(resp)

    return _rate_limited_request('gitlab', do_request, timeout)


_SLACK_REJECTED = frozenset({'invalid_auth', 'not_authed', 'account_inactive',
                             'token_revoked', 'token_expired'})


def validate_slack(matched_text: str, timeout: int = 5) -> dict:
    """Validate Slack token via auth.test."""
    token = re.search(r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)', matched_text)
    if not token:
        return _result(UNKNOWN, error='no_token_found')

    def do_request(t):
        resp = requests.post('https://slack.com/api/auth.test',
                           headers={'Authorization': f'Bearer {token.group(1)}'},
                           timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('ok'):
                return _result(VALID, scope='', info=f"team={data.get('team')}, user={data.get('user')}")
            # Slack answers 200 with ok:false; these errors are its verdict on the token.
            error = str(data.get('error') or '')
            if error in _SLACK_REJECTED:
                return _result(REJECTED, info=f"error={error}")
            return _result(UNKNOWN, info=f"error={error}" if error else '')
        return _no_answer(resp)

    return _rate_limited_request('slack', do_request, timeout)


def validate_stripe(matched_text: str, timeout: int = 5) -> dict:
    """Validate Stripe key via GET /v1/account."""
    token = re.search(r'(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})', matched_text)
    if not token:
        return _result(UNKNOWN, error='no_token_found')

    def do_request(t):
        resp = requests.get('https://api.stripe.com/v1/account',
                          auth=(token.group(1), ''),
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            return _result(VALID, scope='account', info=f"id={data.get('id')}")
        return _no_answer(resp)

    return _rate_limited_request('stripe', do_request, timeout)


def validate_google_maps(matched_text: str, timeout: int = 5) -> dict:
    """Validate Google Maps API key via Geocoding API (key in header not possible, but query param is the standard pattern for Google APIs)."""
    key = re.search(r'(AIza[0-9A-Za-z\-_]{35})', matched_text)
    if not key:
        return _result(UNKNOWN, error='no_key_found')

    def do_request(t):
        # Google Maps APIs require key= in query param (no header auth option).
        # Use Geocoding API with a minimal request to reduce exposure.
        resp = requests.get(
            'https://maps.googleapis.com/maps/api/geocode/json',
            params={'address': 'test', 'key': key.group(1)},
            timeout=t, allow_redirects=False)
        if resp.status_code == 200:
            data = resp.json()
            status = data.get('status', '')
            if status in ('OK', 'ZERO_RESULTS'):
                return _result(VALID, scope='maps', info=f'Geocoding API accessible (status={status})')
            if status == 'REQUEST_DENIED' and 'invalid' in str(data.get('error_message') or '').lower():
                return _result(REJECTED, info='The provided API key is invalid')
            # Denied for this one API (restricted to others, or billing off) or
            # over quota: no verdict on the key itself.
            return _result(UNKNOWN, info=f'Geocoding API answered status={status or "none"}')
        return _no_answer(resp)

    return _rate_limited_request('google', do_request, timeout)


def validate_twilio(matched_text: str, timeout: int = 5) -> dict:
    """Validate Twilio credentials via GET /2010-04-01/Accounts/{SID}."""
    sid = re.search(r'(AC[a-zA-Z0-9]{32})', matched_text)
    api_key = re.search(r'(SK[0-9a-fA-F]{32})', matched_text)
    if not sid:
        return _result(UNKNOWN, error='no_sid_found')

    return _result(UNKNOWN, info='SID found, auth token needed for validation', error='incomplete_credentials')


def validate_sendgrid(matched_text: str, timeout: int = 5) -> dict:
    """Validate SendGrid API key via GET /v3/scopes."""
    key = re.search(r'(SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9\-_]{43})', matched_text)
    if not key:
        return _result(UNKNOWN, error='no_key_found')

    def do_request(t):
        resp = requests.get('https://api.sendgrid.com/v3/scopes',
                          headers={'Authorization': f'Bearer {key.group(1)}'},
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            scopes = data.get('scopes', [])
            return _result(VALID, scope=','.join(scopes[:5]), info=f"{len(scopes)} scopes")
        return _no_answer(resp)

    return _rate_limited_request('sendgrid', do_request, timeout)


def validate_mailgun(matched_text: str, timeout: int = 5) -> dict:
    """Validate Mailgun API key via GET /v3/domains."""
    key = re.search(r'(key-[0-9a-zA-Z]{32})', matched_text)
    if not key:
        return _result(UNKNOWN, error='no_key_found')

    def do_request(t):
        resp = requests.get('https://api.mailgun.net/v3/domains',
                          auth=('api', key.group(1)),
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            domains = [d.get('name', '') for d in data.get('items', [])]
            return _result(VALID, scope='domains', info=f"domains={domains[:3]}")
        return _no_answer(resp)

    return _rate_limited_request('mailgun', do_request, timeout)


def validate_mailchimp(matched_text: str, timeout: int = 5) -> dict:
    """Validate Mailchimp API key via GET /3.0/ping."""
    key = re.search(r'([0-9a-f]{32}-us[0-9]{1,2})', matched_text)
    if not key:
        return _result(UNKNOWN, error='no_key_found')

    dc = key.group(1).split('-')[-1]

    def do_request(t):
        resp = requests.get(f'https://{dc}.api.mailchimp.com/3.0/ping',
                          auth=('anyuser', key.group(1)),
                          timeout=t)
        if resp.status_code == 200:
            return _result(VALID, scope='api', info=f"dc={dc}")
        return _no_answer(resp)

    return _rate_limited_request('mailchimp', do_request, timeout)


def validate_hubspot(matched_text: str, timeout: int = 5) -> dict:
    """Validate HubSpot API key via GET /account-info/v3/api-usage/daily/private-apps with Bearer auth."""
    key = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', matched_text)
    if not key:
        return _result(UNKNOWN, error='no_key_found')

    def do_request(t):
        resp = requests.get('https://api.hubapi.com/account-info/v3/details',
                          headers={'Authorization': f'Bearer {key.group(1)}'},
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            return _result(VALID, scope='api', info=f"portal={data.get('portalId')}")
        return _no_answer(resp)

    return _rate_limited_request('hubspot', do_request, timeout)


def validate_heroku(matched_text: str, timeout: int = 5) -> dict:
    """Validate Heroku API key via GET /account."""
    key = re.search(r'([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})', matched_text, re.IGNORECASE)
    if not key:
        return _result(UNKNOWN, error='no_key_found')

    def do_request(t):
        resp = requests.get('https://api.heroku.com/account',
                          headers={'Authorization': f'Bearer {key.group(1)}', 'Accept': 'application/vnd.heroku+json; version=3'},
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            return _result(VALID, scope='account', info=f"email={data.get('email')}")
        return _no_answer(resp)

    return _rate_limited_request('heroku', do_request, timeout)


def validate_firebase(matched_text: str, timeout: int = 5) -> dict:
    """Validate Firebase database URL by appending .json."""
    url_match = re.search(r'(https://[a-z0-9-]+\.firebaseio\.com)', matched_text)
    if not url_match:
        return _result(UNKNOWN, error='no_url_found')

    def do_request(t):
        resp = requests.get(f'{url_match.group(1)}/.json?shallow=true',
                          timeout=t)
        if resp.status_code == 200:
            return _result(VALID, scope='database', info='Database publicly readable')
        if resp.status_code in (401, 403):
            # The rules refused an anonymous read: the protection works, so it
            # is never proof. A 401 is the database's own refusal; a 403 is
            # left without a verdict, as it is for every validator.
            return _result(REJECTED if resp.status_code == 401 else UNKNOWN,
                           info=f"Database locked, anonymous read refused: status={resp.status_code}")
        return _no_answer(resp)

    return _rate_limited_request('firebase', do_request, timeout)


def validate_digitalocean(matched_text: str, timeout: int = 5) -> dict:
    """Validate DigitalOcean token via GET /v2/account."""
    token = re.search(r'(dop_v1_[a-f0-9]{64})', matched_text)
    if not token:
        return _result(UNKNOWN, error='no_token_found')

    def do_request(t):
        resp = requests.get('https://api.digitalocean.com/v2/account',
                          headers={'Authorization': f'Bearer {token.group(1)}'},
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            acct = data.get('account', {})
            return _result(VALID, scope='account', info=f"status={acct.get('status')}")
        return _no_answer(resp)

    return _rate_limited_request('digitalocean', do_request, timeout)


def validate_telegram(matched_text: str, timeout: int = 5) -> dict:
    """Validate Telegram bot token via getMe."""
    token = re.search(r'([0-9]+:AA[0-9A-Za-z\-_]{33})', matched_text)
    if not token:
        return _result(UNKNOWN, error='no_token_found')

    def do_request(t):
        resp = requests.get(f'https://api.telegram.org/bot{token.group(1)}/getMe',
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('ok'):
                bot = data.get('result', {})
                return _result(VALID, scope='bot', info=f"username=@{bot.get('username')}")
        return _no_answer(resp)

    return _rate_limited_request('telegram', do_request, timeout)


def validate_discord(matched_text: str, timeout: int = 5) -> dict:
    """Validate Discord token via GET /api/v10/users/@me."""
    token = re.search(r'([MN][A-Za-z\d]{23,}\.[\w-]{4,7}\.[\w-]{27,})', matched_text)
    if not token:
        return _result(UNKNOWN, error='no_token_found')

    def do_request(t):
        resp = requests.get('https://discord.com/api/v10/users/@me',
                          headers={'Authorization': f'Bot {token.group(1)}'},
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            return _result(VALID, scope='bot', info=f"username={data.get('username')}")
        return _no_answer(resp)

    return _rate_limited_request('discord', do_request, timeout)


def validate_postmark(matched_text: str, timeout: int = 5) -> dict:
    """Validate Postmark server token via GET /server."""
    token = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', matched_text)
    if not token:
        return _result(UNKNOWN, error='no_token_found')

    def do_request(t):
        resp = requests.get('https://api.postmarkapp.com/server',
                          headers={'X-Postmark-Server-Token': token.group(1), 'Accept': 'application/json'},
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            return _result(VALID, scope='server', info=f"name={data.get('Name')}")
        return _no_answer(resp)

    return _rate_limited_request('postmark', do_request, timeout)


def validate_okta(matched_text: str, timeout: int = 5) -> dict:
    """Validate Okta API token -- requires domain, skipped if not available."""
    return _result(UNKNOWN, info='Okta validation requires domain context', error='incomplete_credentials')


def validate_shopify(matched_text: str, timeout: int = 5) -> dict:
    """Validate Shopify token -- requires store URL, skipped if not available."""
    token = re.search(r'(shpat_[a-fA-F0-9]{32})', matched_text)
    if not token:
        return _result(UNKNOWN, error='no_token_found')
    return _result(UNKNOWN, info='Shopify validation requires store URL', error='incomplete_credentials')


def validate_cloudflare(matched_text: str, timeout: int = 5) -> dict:
    """Validate Cloudflare API token via GET /client/v4/user/tokens/verify."""
    # Extract token from between quotes (patterns include surrounding context),
    # then fall back to a bare 37-40 char alphanumeric string
    quoted = re.search(r"['\"]([A-Za-z0-9_-]{37,40})['\"]", matched_text)
    bare = re.search(r'[A-Za-z0-9_-]{37,40}', matched_text) if not quoted else None
    if not quoted and not bare:
        return _result(UNKNOWN, error='no_token_found')
    token_str = quoted.group(1) if quoted else bare.group(0)

    def do_request(t):
        resp = requests.get('https://api.cloudflare.com/client/v4/user/tokens/verify',
                          headers={'Authorization': f'Bearer {token_str}'},
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('success'):
                result = data.get('result', {})
                return _result(VALID, scope='', info=f"status={result.get('status')}")
        return _no_answer(resp)

    return _rate_limited_request('cloudflare', do_request, timeout)


def validate_openai(matched_text: str, timeout: int = 5) -> dict:
    """Validate OpenAI API key via GET /v1/models."""
    key = re.search(r'(sk-[a-zA-Z0-9_-]{20,})', matched_text)
    if not key:
        return _result(UNKNOWN, error='no_key_found')

    def do_request(t):
        resp = requests.get('https://api.openai.com/v1/models',
                          headers={'Authorization': f'Bearer {key.group(1)}'},
                          timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            model_count = len(data.get('data', []))
            return _result(VALID, scope='api', info=f"{model_count} models accessible")
        return _no_answer(resp)

    return _rate_limited_request('openai', do_request, timeout)


# ---------------------------------------------------------------------------
# Format-only validators (no API calls, structural checks only)
# ---------------------------------------------------------------------------

def validate_twilio_format(matched_text: str, timeout: int = 5) -> dict:
    """Format validation for Twilio Account SID (no API call)."""
    sid = re.search(r'AC([a-zA-Z0-9]{32})', matched_text)
    if not sid:
        return _result(FORMAT_INVALID, info='Not valid format for Twilio SID', error='format_invalid')
    sid_part = sid.group(1)
    freq: dict[str, int] = {}
    for c in sid_part:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((count / len(sid_part)) * math.log2(count / len(sid_part)) for count in freq.values())
    if entropy < 3.0:
        return _result(FORMAT_INVALID, info=f'Low entropy ({entropy:.1f}) suggests non-secret data', error='format_invalid')
    return _result(UNKNOWN, info='Format matches Twilio SID structure (high entropy)', error='format_only')


def validate_twitter_format(matched_text: str, timeout: int = 5) -> dict:
    """Format validation for Twitter Bearer Token (no API call)."""
    token = re.search(r'AAAAAAAAAAAAAAAAAAAAAA([0-9A-Za-z%]+)', matched_text)
    if not token:
        return _result(FORMAT_INVALID, info='', error='format_invalid')
    suffix = token.group(1)
    if len(suffix) < 30:
        return _result(FORMAT_INVALID, info='Token too short for Twitter bearer', error='format_invalid')
    if len(set(suffix)) < 5:
        return _result(FORMAT_INVALID, info='Insufficient character diversity', error='format_invalid')
    return _result(UNKNOWN, info='Format matches Twitter bearer structure', error='format_only')


# Registry mapping validator_ref strings to functions
VALIDATOR_REGISTRY = {
    'validate_aws': validate_aws,
    'validate_github': validate_github,
    'validate_gitlab': validate_gitlab,
    'validate_slack': validate_slack,
    'validate_stripe': validate_stripe,
    'validate_google_maps': validate_google_maps,
    'validate_twilio': validate_twilio,
    'validate_sendgrid': validate_sendgrid,
    'validate_mailgun': validate_mailgun,
    'validate_mailchimp': validate_mailchimp,
    'validate_hubspot': validate_hubspot,
    'validate_heroku': validate_heroku,
    'validate_firebase': validate_firebase,
    'validate_digitalocean': validate_digitalocean,
    'validate_telegram': validate_telegram,
    'validate_discord': validate_discord,
    'validate_postmark': validate_postmark,
    'validate_okta': validate_okta,
    'validate_shopify': validate_shopify,
    'validate_cloudflare': validate_cloudflare,
    'validate_openai': validate_openai,
    'validate_twilio_format': validate_twilio_format,
    'validate_twitter_format': validate_twitter_format,
}


def validate_secret(
    name: str,
    matched_text: str,
    validator_ref: Optional[str] = None,
    timeout: int = 5,
) -> dict:
    """
    Validate a discovered secret using the appropriate service-specific validator.

    Args:
        name: Pattern name that matched
        matched_text: The full matched text containing the secret
        validator_ref: Name of the validator function to use
        timeout: Per-request timeout in seconds

    Returns:
        dict with: valid (bool), state (valid | rejected | unknown |
        format_invalid), scope (str), info (str), error (str)
    """
    if not validator_ref or validator_ref not in VALIDATOR_REGISTRY:
        return _result(UNKNOWN, error='no_validator')

    validator_fn = VALIDATOR_REGISTRY[validator_ref]
    return validator_fn(matched_text, timeout=timeout)
