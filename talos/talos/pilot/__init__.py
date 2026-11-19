"""Stage B1 preparation. No server launch, credentials, trust root or approvals bundled."""
from .contracts import ModelPlan,ModelInjection,LocalModel,Scope
from .backend import LocalModelBackend,ProtocolReplayBackend
from .authority import ApprovalGate
