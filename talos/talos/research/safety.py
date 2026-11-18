"""No provider/HTTP transport exists here; validate proposed network policy only."""
import ipaddress
from urllib.parse import urlsplit

from pydantic import Field
from talos.corpus.models import Model


class NetworkPolicy(Model):
    allowed_origins: tuple[str, ...] = ()
    pinned_addresses: tuple[str, ...] = ()
    allow_loopback_fixture: bool = Field(default=False,strict=True)

    def validate_destination(self,url:str, *, resolved_addresses:tuple[str,...]=(), redirected=False):
        if redirected:
            raise PermissionError('redirects prohibited in research path')
        parsed=urlsplit(url)
        if (parsed.scheme not in ('https','http') or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or '%' in parsed.netloc or '\\' in url):
            raise PermissionError('unsafe/noncanonical destination')
        try:
            port=parsed.port or (443 if parsed.scheme=='https' else 80)
        except ValueError:
            raise PermissionError('invalid port') from None
        origin=f'{parsed.scheme}://{parsed.hostname.lower()}:{port}'
        if origin not in self.allowed_origins:
            raise PermissionError('origin not explicitly allowlisted')
        try: literal=(str(ipaddress.ip_address(parsed.hostname)),)
        except ValueError: literal=()
        addresses=literal or resolved_addresses
        if not addresses:
            raise PermissionError('explicit pinned DNS resolution required; no implicit lookup')
        for address in addresses:
            try: ip=ipaddress.ip_address(address)
            except ValueError: raise PermissionError('invalid address') from None
            if str(ip) not in self.pinned_addresses:
                raise PermissionError('DNS/address changed or not pinned')
            # IPv4-mapped IPv6 and metadata/link-local/private/multicast/unspecified denied.
            if getattr(ip,'ipv4_mapped',None) or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                raise PermissionError('unsafe destination address')
            if ip.is_loopback:
                if not self.allow_loopback_fixture: raise PermissionError('loopback requires explicit fixture permission')
            elif not ip.is_global:
                raise PermissionError('private/reserved destination denied')
            if parsed.scheme!='https' and not ip.is_loopback:
                raise PermissionError('external plaintext HTTP denied')
        return origin

    def request(self,*args,**kwargs):
        raise PermissionError('network transport unavailable; allowlist is not endpoint authorization')


class InferenceGate(Model):
    opt_in: bool = Field(default=False,strict=True)
    model_id: str | None = None
    approval_reference: str | None = None

    def invoke(self,*args,**kwargs):
        if not self.opt_in or not self.model_id or not self.approval_reference:
            raise PermissionError('explicit model opt-in, identity and approval reference required')
        raise PermissionError('provider adapter unavailable in PR-05; no inference authorized by metadata')
