import asyncio

import dns.resolver
import dns.reversename


async def get_ptr_record(ip_address: str) -> str | None:
    """Reverse-DNS lookup; returns the PTR hostname (without trailing dot) or None."""
    try:
        loop = asyncio.get_event_loop()
        rev_name = dns.reversename.from_address(ip_address)
        answers = await loop.run_in_executor(
            None, dns.resolver.resolve, rev_name, "PTR"
        )
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


async def get_ptr_records(ip_address: str) -> list[str]:
    """Reverse-DNS lookup; returns all PTR hostnames for *ip_address*
    as lower-cased strings without trailing dots.
    Returns an empty list if the lookup fails or yields no results."""
    try:
        loop = asyncio.get_event_loop()
        rev_name = dns.reversename.from_address(ip_address)
        answers = await loop.run_in_executor(
            None, dns.resolver.resolve, rev_name, "PTR"
        )
        return [str(a).rstrip(".").lower() for a in answers]
    except Exception:
        return []


async def get_a_records(hostname: str) -> list[str]:
    """A record lookup; returns a list of IPv4 addresses for *hostname*,
    or an empty list if the lookup fails or yields no results."""
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(None, dns.resolver.resolve, hostname, "A")
        return [str(a) for a in answers]
    except Exception:
        return []
