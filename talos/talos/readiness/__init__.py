"""Stage A readiness and offline agent controls; empirical execution remains NO-GO."""
from .contracts import EngineeringPlan,Identity,Injection,Reply,ToolCall,ProviderUsage,ModelConfiguration
from .gates import report,CapabilityRequest,ApprovalClaim
from .runtime import execute
from .replay import replay
