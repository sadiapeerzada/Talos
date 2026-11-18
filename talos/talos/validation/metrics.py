"""Explicit denominators and whole-cluster resampling; no validation certification."""
from __future__ import annotations

from collections import Counter,defaultdict
import math
import random
from typing import Literal

from pydantic import Field
from talos.corpus.models import Model
from talos.judging import Outcome

CATEGORIES=tuple(o.value for o in Outcome)


class Bootstrap(Model):
    method: Literal['whole_cluster_percentile'] = 'whole_cluster_percentile'
    seed: int = Field(strict=True)
    resamples: int = Field(ge=100,le=10000,strict=True)
    confidence: float = Field(gt=0,lt=1,allow_inf_nan=False)


def ratio(n,d): return n/d if d else None


def estimate(n,d): return {'numerator':n,'denominator':d,'value':ratio(n,d),'interval':None}


def _base(rows):
    matrix={reference:{prediction:0 for prediction in CATEGORIES} for reference in CATEGORIES}
    for row in rows: matrix[row['reference']][row['prediction']]+=1
    n=len(rows);per_class={}
    for category in CATEGORIES:
        tp=matrix[category][category]
        fp=sum(matrix[r][category] for r in CATEGORIES if r!=category)
        fn=sum(matrix[category][p] for p in CATEGORIES if p!=category)
        tn=n-tp-fp-fn
        per_class[category]={'tp':tp,'fp':fp,'fn':fn,'tn':tn,
            'precision':estimate(tp,tp+fp),'recall':estimate(tp,tp+fn),
            'false_positive_rate':estimate(fp,fp+tn),'false_negative_rate':estimate(fn,fn+tp)}
    known=[r for r in rows if r['reference']!='UNKNOWN']
    selective=[r for r in known if r['prediction']!='UNKNOWN']
    negative=[r for r in known if r['reference']!='CONFIRMED']
    positive=[r for r in known if r['reference']=='CONFIRMED']
    selected_positive=[r for r in known if r['prediction']=='CONFIRMED']
    return {'confusion_matrix':matrix,'per_class':per_class,
        'five_way_accuracy':estimate(sum(r['reference']==r['prediction'] for r in rows),n),
        'reference_known_accuracy':estimate(sum(r['reference']==r['prediction'] for r in known),len(known)),
        'selective_accuracy':estimate(sum(r['reference']==r['prediction'] for r in selective),len(selective)),
        'coverage':estimate(sum(r['prediction']!='UNKNOWN' for r in rows),n),
        'oracle_unknown_rate':estimate(sum(r['prediction']=='UNKNOWN' for r in rows),n),
        'reference_unknown_rate':estimate(n-len(known),n),
        'confirmed_violation':{
            'false_positive_rate_verified_references':estimate(sum(r['prediction']=='CONFIRMED' for r in negative),len(negative)),
            'miss_or_abstain_rate_verified_positives':estimate(sum(r['prediction']!='CONFIRMED' for r in positive),len(positive)),
            'precision_verified_references':estimate(sum(r['reference']=='CONFIRMED' for r in selected_positive),len(selected_positive)),
            'unknown_reference_excluded':n-len(known)},
        'denominators':{'paired_actions':n,'reference_known_actions':len(known),'selective_actions':len(selective),
                        'case_units':len({r['case'] for r in rows}),'target_units':len({r['target'] for r in rows}),
                        'declared_clusters':len({r['cluster'] for r in rows})}}


def _estimates(tree,path=()):
    if isinstance(tree,dict):
        if {'numerator','denominator','value','interval'}<=set(tree): yield path,tree
        else:
            for key,value in tree.items(): yield from _estimates(value,(*path,key))


def _get(tree,path):
    for key in path: tree=tree[key]
    return tree


def _quantile(values,p):
    position=(len(values)-1)*p;left=math.floor(position);right=math.ceil(position)
    return values[left]+(values[right]-values[left])*(position-left)


def _interval(values,spec,clusters):
    defined=sorted(v for v in values if v is not None)
    if clusters<2:
        return {'lower':None,'upper':None,'reason':'fewer than two declared clusters','valid_resamples':0,
                'undefined_resamples':spec.resamples,'method':spec.method}
    if not defined:
        return {'lower':None,'upper':None,'reason':'all resampled denominators undefined','valid_resamples':0,
                'undefined_resamples':spec.resamples,'method':spec.method}
    alpha=(1-spec.confidence)/2
    return {'lower':_quantile(defined,alpha),'upper':_quantile(defined,1-alpha),
        'method':spec.method,'confidence':spec.confidence,'valid_resamples':len(defined),
        'undefined_resamples':len(values)-len(defined),
        'scope':'descriptive; conditional on defined replicates and declared cluster independence'}


def analyze_pairs(rows:list[dict], *, provenance:Literal['synthetic_engineering_only','supplied_human_references'], bootstrap:Bootstrap|None=None):
    """Input rows are paired action units, never implicitly case/target votes."""
    if provenance not in ('synthetic_engineering_only','supplied_human_references'): raise ValueError('explicit reference provenance required')
    ids=[r['sample_id'] for r in rows]
    if len(set(ids))!=len(ids): raise ValueError('duplicate paired action sample')
    for row in rows:
        if row['reference'] not in CATEGORIES or row['prediction'] not in CATEGORIES or not row['cluster']:
            raise ValueError('unknown category or missing cluster identity')
    result=_base(rows);result['provenance']=provenance
    result['unit']='action';result['certification']='NOT_CERTIFIED'
    result['case_level_accuracy']=None;result['target_level_accuracy']=None
    result['aggregation_note']='No approved case/target aggregation rule; counts are distinct units, not independent trials.'
    if bootstrap:
        bootstrap=Bootstrap.model_validate(bootstrap.model_dump())
        grouped=defaultdict(list)
        for row in rows: grouped[row['cluster']].append(row)
        clusters=sorted(grouped);rng=random.Random(bootstrap.seed)
        paths=[path for path,_ in _estimates(result)];replicates={path:[] for path in paths}
        if len(clusters)>=2:
            for _ in range(bootstrap.resamples):
                sample=[r for key in rng.choices(clusters,k=len(clusters)) for r in grouped[key]]
                estimate_tree=_base(sample)
                for path in paths: replicates[path].append(_get(estimate_tree,path)['value'])
        for path in paths:
            target=_get(result,path)
            if target['denominator']==0:
                target['interval']={'lower':None,'upper':None,'reason':'original denominator zero','valid_resamples':0}
            else: target['interval']=_interval(replicates[path],bootstrap,len(clusters))
        result['bootstrap']=bootstrap.model_dump(mode='json')
    return result


def _agreement(rows):
    n=len(rows);agree=sum(r['first']==r['second'] for r in rows)
    first=Counter(r['first'] for r in rows);second=Counter(r['second'] for r in rows)
    pe=sum(first[c]*second[c] for c in CATEGORIES)/(n*n) if n else None
    po=ratio(agree,n)
    kappa=(po-pe)/(1-pe) if n and pe!=1 else None
    return {'paired_review_actions':n,'raw_agreement':estimate(agree,n),'disagreement_rate':estimate(n-agree,n),
            'kappa':{'value':kappa,'denominator':n,'expected_agreement':pe,'interval':None,
                     'undefined_reason':'no paired ratings' if not n else ('single-category degenerate marginals' if pe==1 else None)}}


def agreement(rows:list[dict], *, bootstrap:Bootstrap|None=None):
    if len({r['sample_id'] for r in rows})!=len(rows): raise ValueError('duplicate agreement action')
    if any(r['first'] not in CATEGORIES or r['second'] not in CATEGORIES or not r['cluster'] for r in rows):
        raise ValueError('invalid reviewer category/cluster')
    result=_agreement(rows)
    if bootstrap:
        bootstrap=Bootstrap.model_validate(bootstrap.model_dump());groups=defaultdict(list)
        for row in rows: groups[row['cluster']].append(row)
        keys=sorted(groups);rng=random.Random(bootstrap.seed);values=[];raw=[]
        if len(keys)>=2:
            for _ in range(bootstrap.resamples):
                sample=[row for key in rng.choices(keys,k=len(keys)) for row in groups[key]]
                a=_agreement(sample);values.append(a['kappa']['value']);raw.append(a['raw_agreement']['value'])
        result['kappa']['interval']=_interval(values,bootstrap,len(keys))
        result['raw_agreement']['interval']=_interval(raw,bootstrap,len(keys))
    return result
