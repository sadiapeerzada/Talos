"""Explicit synthetic engineering declarations, never human study approvals."""
from pathlib import Path
from talos.corpus import content_hash, load_corpus, load_bindings
from talos.research.contracts import Cell, DIMENSIONS, Limits, RunPlan, TrustDeclaration, capture_provenance
from talos.targets.store import POLICY_VERSION

ROOT=Path(__file__).parents[2]


def control_plan(environment, *, suffix='DIRECT', trust=False, count=1, timeout_ms=10000, **changes):
    corpus=load_corpus()
    rec=next(r for r in corpus.records if r.case.case_id=='TP1-'+suffix)
    binding=next(b for b in load_bindings().bindings if b.case_identity==rec.identity and b.domain==environment.domain.domain_id)
    declaration=TrustDeclaration(reference='unit-test-only:explicit-synthetic-declaration-not-human-approval',
        policy_id=environment.domain.policy_id,policy_version=POLICY_VERSION,
        trusted_source_ids=(environment.source_id,)) if trust else None
    amounts={d:0 for d in DIMENSIONS};amounts.update(attempts=count,target_calls=count*2,elapsed_ms=timeout_ms*count)
    plan=RunPlan(run_id='synthetic-unit-test',provenance=capture_provenance(ROOT,ROOT/'talos/requirements-research.lock'),
        corpus_sha256=content_hash(corpus),profile=environment.profile(),target_version=environment.profile().fixture_id,
        policy_id=environment.domain.policy_id,policy_version=POLICY_VERSION,seed=73,timeout_ms=timeout_ms,
        limits=Limits(amounts=amounts),trust=declaration,
        cells=tuple(Cell(cell_id=f'cell-{i}',scenario_id='synthetic-engineering',repeat_id=f'repeat-{i}',
            case_identity=rec.identity,binding_id=binding.binding_id,mode='direct_fixture_control') for i in range(count)))
    raw=plan.model_dump();raw.update(changes)
    return RunPlan.model_validate(raw)
