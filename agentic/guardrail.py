"""
Target Guardrail — LLM-based check to prevent targeting unauthorized domains/IPs.

Blocks well-known public websites, government domains, major tech companies, etc.
For IP mode: resolves public IPs via reverse DNS, then checks resolved hostnames.
Private/RFC1918 IPs are auto-allowed. Unresolvable public IPs are auto-allowed.
"""

import asyncio
import ipaddress
import json
import logging
import socket
from typing import Any

from langchain_core.messages import SystemMessage, HumanMessage

from orchestrator_helpers.json_utils import normalize_content, extract_json

logger = logging.getLogger(__name__)

GUARDRAIL_SYSTEM_PROMPT = """You are a security guardrail for a penetration testing platform.
Your job is to evaluate whether a target domain is safe to allow for scanning.

You must BLOCK targets that are:
- Government or military websites (domains containing .gov, .mil, or their country variants like .gov.uk, .gov.it, .gouv.fr, etc.)
- Major tech companies (google.com, amazon.com, microsoft.com, apple.com, meta.com, facebook.com, twitter.com, x.com, netflix.com, adobe.com, oracle.com, salesforce.com, ibm.com, intel.com, nvidia.com, etc. and ALL their subdomains/variants)
- Major cloud providers (aws.amazon.com, cloud.google.com, azure.microsoft.com, cloudflare.com, akamai.com, fastly.com, etc.)
- Social media platforms (instagram.com, tiktok.com, linkedin.com, reddit.com, pinterest.com, snapchat.com, youtube.com, twitch.tv, discord.com, telegram.org, whatsapp.com, etc.)
- Major financial institutions and banks (paypal.com, stripe.com, visa.com, mastercard.com, jpmorgan.com, bankofamerica.com, chase.com, wellsfargo.com, goldmansachs.com, etc.)
- Major e-commerce platforms (ebay.com, shopify.com, alibaba.com, walmart.com, target.com, bestbuy.com, etc.)
- Healthcare organizations (who.int, cdc.gov, nih.gov, etc.)
- Educational institutions (.edu domains)
- Critical infrastructure (DNS root servers, major ISPs, ICANN, etc.)
- Major news/media organizations (cnn.com, bbc.com, nytimes.com, reuters.com, etc.)
- Domains of major open-source projects and foundations (apache.org, linux.org, mozilla.org, wikipedia.org, etc.)

You must ALLOW targets that are:
- Custom or obscure domains that look like they belong to a small company or individual
- Internal/lab domains (.local, .internal, .test, .lab, .home, .lan)
- Domains that appear to be legitimate pentest targets or intentionally vulnerable apps (e.g., vulnhub.com, hackthebox.com, tryhackme.com, vulnweb.com, testphp.vulnweb.com, juice-shop, DVWA, WebGoat, etc.)
- Any domain that is not EXPLICITLY listed in the block list above
- Any domain you are not 100% sure belongs to a major company, government, or critical service

IMPORTANT: Be lenient. When in doubt, ALLOW. Only block domains you are absolutely certain belong to the categories listed above. This is a penetration testing platform — users are expected to scan targets they own or have permission to test. Do not block unknown or unfamiliar domains.

Output ONLY valid JSON with this exact format:
{"allowed": true/false, "reason": "brief explanation"}"""

GUARDRAIL_DOMAIN_PROMPT = """Evaluate this target domain for a penetration testing scan:

Target domain: {target}

Should this target be allowed or blocked? Remember: block well-known/public/government/major-company domains. Allow obscure/custom/small-org domains."""

GUARDRAIL_IP_RESOLVED_PROMPT = """Evaluate these target IPs and their resolved hostnames for a penetration testing scan:

Target IPs: {ips}
Resolved hostnames: {hostnames}

Should these targets be allowed or blocked? Judge based on the resolved hostnames. Block if any hostname belongs to a well-known/public/government/major-company domain."""


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/RFC1918/loopback."""
    try:
        # Strip CIDR notation for the check
        addr_str = ip_str.split("/")[0]
        addr = ipaddress.ip_address(addr_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def resolve_ips(target_ips: list[str]) -> list[str]:
    """Reverse-DNS resolve public IPs to hostnames.

    Skips private IPs (auto-allowed). Returns list of resolved hostnames.
    IPs with no PTR record are silently skipped.
    """
    hostnames = []
    for ip_str in target_ips:
        addr_str = ip_str.split("/")[0]  # Strip CIDR
        if is_private_ip(addr_str):
            continue
        try:
            hostname, _, _ = socket.gethostbyaddr(addr_str)
            if hostname and hostname != addr_str:
                hostnames.append(hostname)
                logger.info(f"Guardrail: {addr_str} -> {hostname}")
        except (socket.herror, socket.gaierror, OSError):
            logger.debug(f"Guardrail: no PTR record for {addr_str}")
    return hostnames


async def check_target_allowed(
    llm: Any,
    target_domain: str = "",
    target_ips: list[str] | None = None,
) -> dict[str, Any]:
    """Check if a target domain or IP list is allowed for scanning.

    Args:
        llm: LangChain LLM instance.
        target_domain: Domain string (for domain mode).
        target_ips: List of IPs/CIDRs (for IP mode).

    Returns:
        {"allowed": bool, "reason": str}
    """
    if target_ips is None:
        target_ips = []

    # --- Domain mode ---
    if target_domain:
        return await _check_domain(llm, target_domain)

    # --- IP mode ---
    if not target_ips:
        return {"allowed": True, "reason": "No targets specified"}

    # All private IPs? Auto-allow.
    all_private = all(is_private_ip(ip.split("/")[0]) for ip in target_ips)
    if all_private:
        logger.info("Guardrail: all IPs are private/RFC1918, auto-allowing")
        return {"allowed": True, "reason": "All targets are private/internal IPs"}

    # Resolve public IPs to hostnames (run in thread to avoid blocking event loop)
    hostnames = await asyncio.to_thread(resolve_ips, target_ips)

    # No hostnames resolved? Auto-allow (unknown IPs are likely legit pentest targets).
    if not hostnames:
        logger.info("Guardrail: no PTR records found for public IPs, auto-allowing")
        return {"allowed": True, "reason": "No recognizable hostnames resolved from target IPs"}

    # Check resolved hostnames via LLM
    return await _check_ips_with_hostnames(llm, target_ips, hostnames)


async def _check_domain(llm: Any, domain: str) -> dict[str, Any]:
    """Ask LLM whether a domain is allowed."""
    prompt = GUARDRAIL_DOMAIN_PROMPT.format(target=domain)
    return await _invoke_guardrail(llm, prompt)


async def _check_ips_with_hostnames(
    llm: Any, ips: list[str], hostnames: list[str]
) -> dict[str, Any]:
    """Ask LLM whether IPs (with resolved hostnames) are allowed."""
    prompt = GUARDRAIL_IP_RESOLVED_PROMPT.format(
        ips=", ".join(ips),
        hostnames=", ".join(hostnames),
    )
    return await _invoke_guardrail(llm, prompt)


async def _invoke_guardrail(llm: Any, user_prompt: str) -> dict[str, Any]:
    """Send guardrail prompt to LLM and parse JSON response."""
    messages = [
        SystemMessage(content=GUARDRAIL_SYSTEM_PROMPT),
        HumanMessage(content=user_prompt),
    ]

    for attempt in range(3):
        try:
            response = await llm.ainvoke(messages)
            text = normalize_content(response.content)
            json_str = extract_json(text)

            if json_str:
                result = json.loads(json_str)
                allowed = result.get("allowed", True)
                reason = result.get("reason", "No reason provided")
                logger.info(f"Guardrail result: allowed={allowed}, reason={reason}")
                return {"allowed": bool(allowed), "reason": str(reason)}

            logger.warning(f"Guardrail attempt {attempt + 1}: no JSON in response")

        except Exception as e:
            logger.warning(f"Guardrail attempt {attempt + 1} error: {e}")

    # All retries exhausted — raise so callers can decide fail-open vs fail-closed
    raise RuntimeError("Guardrail LLM check failed after 3 attempts")
