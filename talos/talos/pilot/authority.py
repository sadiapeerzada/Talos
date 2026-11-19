"""Verify only externally supplied records; no signer, key generator or default trust."""
from datetime import datetime,timezone
from pathlib import Path
from typing import Literal
import hashlib,importlib.metadata,json
from pydantic import Field,field_validator
from talos.corpus.models import Model
from talos.research.recorder import canonical
from talos.pilot.contracts import Scope,H

ROLES=('target_owner','principal_researcher','budget_owner','evidence_custodian','reviewer_one','reviewer_two','adjudicator')
EVIDENCE=('ownership_policy_delivery','model_provider_custody','containment_cancellation','budget_pricing',
          'dev_cases_information','independent_review','dev_protocol')
DOMAIN=b'TALOS_DEV_PILOT_APPROVAL_V1\x00'


class Authority(Model):
    authority_id:str=Field(min_length=1)
    public_key_hex:str=Field(pattern=r'^[0-9a-f]{64}$')
    roles:tuple[str,...]
    independence_group:str=Field(min_length=1)
    revoked:bool=Field(strict=True)


class Registry(Model):
    schema_version:Literal['talos.external-authority-registry.v1']='talos.external-authority-registry.v1'
    valid_until:datetime
    authorities:tuple[Authority,...]

    @field_validator('valid_until')
    @classmethod
    def aware(cls,value):
        if value.tzinfo is None:raise ValueError('UTC-aware expiry required')
        return value


class Approval(Model):
    schema_version:Literal['talos.signed-DEV-pilot-approval.v1']='talos.signed-DEV-pilot-approval.v1'
    approval_id:str=Field(min_length=1)
    decision:Literal['APPROVE_DEV_PILOT']='APPROVE_DEV_PILOT'
    authority_id:str=Field(min_length=1)
    role:str
    scope_sha256:str=Field(pattern=H)
    not_before:datetime
    expires_at:datetime
    evidence_sha256:dict[str,str]
    signature_hex:str=Field(pattern=r'^[0-9a-f]{128}$',repr=False)

    @field_validator('not_before','expires_at')
    @classmethod
    def aware(cls,value):
        if value.tzinfo is None:raise ValueError('UTC-aware validity required')
        return value

    def signed_bytes(self):return DOMAIN+canonical(self.model_dump(mode='json',exclude={'signature_hex'}))


def verify_signature(public_key:bytes,signature:bytes,message:bytes):
    # Public verification only. Missing optional implementation fails closed.
    if importlib.metadata.version('cryptography')!='50.0.2':raise PermissionError('pinned crypto verifier unavailable')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature,message)


def file_hash(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise PermissionError('required regular custody file absent')
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1048576),b''):digest.update(chunk)
    return digest.hexdigest()


class ApprovalGate:
    """Trust-root hash/records must come from the real operator out of band.

    A hash does not authenticate who supplied it. No bundled root is provided.
    Re-read roots, revocations, evidence and approvals before every request/tool.
    """
    def __init__(self, *, registry_path:Path|None=None,registry_sha256:str|None=None,
                 approval_paths:tuple[Path,...]=(),evidence_paths:dict|None=None):
        self.registry_path=registry_path;self.registry_sha256=registry_sha256
        self.approval_paths=approval_paths;self.evidence_paths=evidence_paths or {}

    def require(self,scope:Scope, *, opt_in:bool=False,now:datetime|None=None):
        if opt_in is not True:raise PermissionError('explicit DEV inference opt-in absent')
        if not self.registry_path or not self.registry_sha256:raise PermissionError('genuinely supplied authority trust root absent')
        now=now or datetime.now(timezone.utc)
        if now.tzinfo is None:raise PermissionError('aware verification clock required')
        if file_hash(self.registry_path)!=self.registry_sha256:raise PermissionError('out-of-band authority root changed/unverified')
        registry=Registry.model_validate(__import__('talos.pilot.protocol',fromlist=['loads']).loads(Path(self.registry_path).read_text()))
        if registry.valid_until<=now:raise PermissionError('authority registry expired')
        ids=[a.authority_id for a in registry.authorities]
        if len(set(ids))!=len(ids):raise PermissionError('duplicate authority identity')
        authorities={a.authority_id:a for a in registry.authorities}
        if set(self.evidence_paths)!=set(EVIDENCE):raise PermissionError('required independent custody/budget/DEV evidence absent')
        hashes={k:file_hash(p) for k,p in self.evidence_paths.items()}
        if hashes['model_provider_custody']!=scope.model_custody_sha256 or hashes['containment_cancellation']!=scope.cancellation_sha256:
            raise PermissionError('scope/custody evidence mismatch')
        approvals=[]
        for path in self.approval_paths:
            file_hash(path);approval=Approval.model_validate(__import__('talos.pilot.protocol',fromlist=['loads']).loads(Path(path).read_text()));authority=authorities.get(approval.authority_id)
            if not authority or authority.revoked or approval.role not in authority.roles or approval.role not in ROLES:
                raise PermissionError('unknown/revoked/unentitled approval authority')
            if approval.scope_sha256!=scope.digest() or approval.evidence_sha256!=hashes or not approval.not_before<=now<approval.expires_at:
                raise PermissionError('wrong scope/evidence or expired/not-yet-valid approval')
            try:verify_signature(bytes.fromhex(authority.public_key_hex),bytes.fromhex(approval.signature_hex),approval.signed_bytes())
            except Exception:raise PermissionError('signature verification failed/unavailable') from None
            approvals.append(approval)
        if sorted(a.role for a in approvals)!=sorted(ROLES) or len({a.approval_id for a in approvals})!=len(approvals):
            raise PermissionError('complete unique role approvals required')
        owner_keys={authorities[a.authority_id].public_key_hex for a in approvals if a.role in ('target_owner','principal_researcher')}
        owners={authorities[a.authority_id].independence_group for a in approvals if a.role in ('target_owner','principal_researcher')}
        reviewers=[authorities[a.authority_id] for a in approvals if a.role in ('reviewer_one','reviewer_two','adjudicator')]
        if len({a.authority_id for a in reviewers})!=3 or len({a.independence_group for a in reviewers})!=3 or len({a.public_key_hex for a in reviewers})!=3 or any(a.public_key_hex in owner_keys for a in reviewers) or any(a.independence_group in owners for a in reviewers):
            raise PermissionError('independent reviewer/adjudicator custody not established')
        return {'status':'VERIFIED_SUPPLIED_RECORDS','scope_sha256':scope.digest(),'registry_sha256':self.registry_sha256,
            'approval_ids':[a.approval_id for a in approvals],'approval_sha256':[file_hash(p) for p in self.approval_paths],'evidence_sha256':hashes,
            'limitation':'cryptographic binding relies on genuine out-of-band registry provenance; does not itself establish label validity'}
