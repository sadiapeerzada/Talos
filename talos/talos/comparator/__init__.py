"""Offline external comparator engineering; actual provider execution disabled."""
from .contracts import Config,Mapping,Plan,NativeReceipt,NormalizedResult
from .matching import dry_run
from .runtime import execute
