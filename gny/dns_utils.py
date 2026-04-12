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
