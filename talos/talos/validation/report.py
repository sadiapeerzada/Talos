"""Reference-comparison gates and missing/unresolved accounting, never certification."""
from collections import Counter,defaultdict
from pathlib import Path

from talos.research.recorder import verify
from talos.validation.metrics import Bootstrap,agreement,analyze_pairs,estimate
from talos.validation.workflow import Study,differences,reviews_for


def validation_report(study:Study, *, expected_seal:str, calibration=False, bootstrap:Bootstrap|None=None):
    verify(study.path,expected_seal=expected_seal)
    state=study.state();protocol=state['protocol']
    pending=protocol.pending_gates();accounting=Counter();rows=[];ratings=[];unresolved=[]
    # Declared clusters that split a case/target need correction before inferential intervals.
    units=defaultdict(set)
    for sample in state['samples'].values():
        units[('case',sample.case_unit_id)].add(sample.independence_cluster_id)
        units[('target',sample.target_unit_id)].add(sample.independence_cluster_id)
        units[('source_case',sample.source_case_identity)].add(sample.independence_cluster_id)
        units[('source_target_instance',sample.source_target_id)].add(sample.independence_cluster_id)
        for ancestor in sample.related_case_ids:
            units[('related_case',ancestor)].add(sample.independence_cluster_id)
    cluster_conflicts=[{'unit':kind,'id':ident,'clusters':sorted(clusters)} for (kind,ident),clusters in units.items() if len(clusters)>1]
    for sid,sample in state['samples'].items():
        reviews=reviews_for(state,sid)
        accounting['planned_actions']+=1
        accounting['missing_initial_reviews']+=2-len(reviews)
        synthetic=any(r.origin!='human_supplied' for r in reviews)
        leakage=any(not r.blinded for r in reviews)
        if leakage: accounting['blinding_compromised_actions']+=1
        eligible=calibration or (protocol.purpose=='independent_human_review' and not pending and not synthetic and not leakage)
        if len(reviews)==2 and eligible:
            ratings.append({'sample_id':sid,'first':reviews[0].label.outcome.value,'second':reviews[1].label.outcome.value,
                            'cluster':sample.independence_cluster_id})
        final=None;why=None
        if len(reviews)!=2: why='missing_initial_reviews'
        elif leakage: why='blinding_compromised'
        else:
            diff=differences(reviews[0].label,reviews[1].label)
            if diff: accounting['fact_or_category_disagreements']+=1
            adjudication=state['adjudications'].get(sid)
            if adjudication:
                if not adjudication.blinded:
                    eligible=False;why='adjudicator_blinding_compromised'
                    accounting['blinding_compromised_actions']+=1
                if not calibration and adjudication.origin!='human_supplied':
                    eligible=False;synthetic=True
                final=adjudication.label
                accounting['adjudicated_actions']+=1
            elif diff: why='unresolved_adjudication'
            else: final=reviews[0].label
        if not eligible:
            if synthetic: accounting['synthetic_reference_actions_excluded']+=1
            why=why or 'human_protocol_or_provenance_gate_pending'
        if why:
            unresolved.append({'sample_id':sid,'reason':why});accounting['missing_reference_actions']+=1
            if why=='unresolved_adjudication': accounting['unresolved_adjudications']+=1
            continue
        if final is not None:
            rows.append({'sample_id':sid,'reference':final.outcome.value,'prediction':state['predictions'][sid].verdict.status.value,
                'cluster':sample.independence_cluster_id,'case':sample.case_unit_id,'target':sample.target_unit_id,
                'domain':sample.domain,'effect_type':sample.effect_type,'policy_boundary':sample.policy_boundary,
                'evidence_condition':sample.evidence_condition})
    predictions=list(state['predictions'].values())
    accounting['paired_reference_actions']=len(rows)
    scope='synthetic_engineering_only' if calibration else 'supplied_human_references'
    intervals=bootstrap if not cluster_conflicts else None
    metrics=analyze_pairs(rows,provenance=scope,bootstrap=intervals) if rows else None
    strata={}
    for axis in ('domain','effect_type','policy_boundary','evidence_condition'):
        strata[axis]={}
        values=sorted({getattr(s,axis) for s in state['samples'].values()})
        for value in values:
            matched=[row for row in rows if row[axis]==value]
            strata[axis][value]={'planned_actions':sum(getattr(s,axis)==value for s in state['samples'].values()),
                'paired_actions':len(matched),'metrics':analyze_pairs(matched,provenance=scope,bootstrap=intervals) if matched else None}
    return {'schema_version':'talos.validation-report.v1','study_seal':expected_seal,
        'status':'SYNTHETIC_ENGINEERING_ONLY' if calibration else ('REFERENCE_COMPARISON_ONLY' if rows else 'PENDING'),
        'certification':'NOT_INDEPENDENTLY_CERTIFIED','pending_gates':pending,
        'accounting':{key:accounting[key] for key in ('planned_actions','missing_initial_reviews','missing_reference_actions',
            'paired_reference_actions','blinding_compromised_actions','fact_or_category_disagreements','adjudicated_actions',
            'unresolved_adjudications','synthetic_reference_actions_excluded')},
        'unit_counts':{'action':len(state['samples']),'case':len({s.case_unit_id for s in state['samples'].values()}),
                       'target':len({s.target_unit_id for s in state['samples'].values()}),
                       'declared_cluster':len({s.independence_cluster_id for s in state['samples'].values()}),
                       'source_cases':len({s.source_case_identity for s in state['samples'].values()}),
                       'source_target_instances':len({s.source_target_id for s in state['samples'].values()})},
        'operational_prediction_unknown_rate':estimate(sum(p.verdict.status.value=='UNKNOWN' for p in predictions),len(predictions)),
        'operational_rate_note':'Prediction abstention accounting only; not measured oracle accuracy.',
        'unresolved':unresolved,'cluster_conflicts':cluster_conflicts,
        'metrics':metrics,'agreement':agreement(ratings,bootstrap=intervals) if ratings else None,'strata':strata}
