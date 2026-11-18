"""Hand-calculated toy mathematics, never measured human-validation results."""
from copy import deepcopy
import random

import pytest

from talos.validation.metrics import Bootstrap,agreement,analyze_pairs


def pairs():
    categories=[('CONFIRMED','CONFIRMED'),('CONFIRMED','BLOCKED'),('BLOCKED','BLOCKED'),
                ('NO_VIOLATION','NO_VIOLATION'),('UNKNOWN','CONFIRMED'),('ATTEMPTED','UNKNOWN')]
    return [dict(sample_id=f'toy-{i}',reference=r,prediction=p,cluster=f'cluster-{i}',case=f'case-{i}',
                 target=f'target-{i}') for i,(r,p) in enumerate(categories)]


def analyze(rows,**kwargs): return analyze_pairs(rows,provenance='synthetic_engineering_only',**kwargs)


def test_hand_calculated_five_way_and_confirmed_effect_denominators():
    result=analyze(pairs())
    assert sum(sum(row.values()) for row in result['confusion_matrix'].values())==6
    assert result['confusion_matrix']['UNKNOWN']['CONFIRMED']==1
    assert result['five_way_accuracy']['numerator']==3 and result['five_way_accuracy']['denominator']==6
    assert result['reference_known_accuracy']['value']==3/5
    assert result['selective_accuracy']['value']==3/4
    assert result['coverage']['value']==5/6
    assert result['oracle_unknown_rate']['value']==1/6
    assert result['reference_unknown_rate']['value']==1/6
    confirmed=result['per_class']['CONFIRMED']
    assert (confirmed['tp'],confirmed['fp'],confirmed['fn'],confirmed['tn'])==(1,1,1,3)
    assert confirmed['precision']['value']==.5 and confirmed['recall']['value']==.5
    assert confirmed['false_positive_rate']['value']==.25
    # UNKNOWN references are not established negative effect truth.
    primary=result['confirmed_violation']
    assert primary['false_positive_rate_verified_references']['numerator']==0
    assert primary['false_positive_rate_verified_references']['denominator']==3
    assert primary['precision_verified_references']['value']==1
    assert primary['miss_or_abstain_rate_verified_positives']['value']==.5
    assert primary['unknown_reference_excluded']==1
    assert result['case_level_accuracy'] is None and result['target_level_accuracy'] is None
    assert result['certification']=='NOT_CERTIFIED'


def test_unknown_matches_cannot_inflate_selective_accuracy():
    rows=pairs()
    rows.extend(dict(sample_id=f'unknown-{i}',reference='UNKNOWN',prediction='UNKNOWN',cluster=f'u-{i}',case=f'u-{i}',target=f'u-{i}') for i in range(20))
    result=analyze(rows)
    assert result['five_way_accuracy']['value']==23/26
    assert result['selective_accuracy']['value']==.75
    assert result['reference_known_accuracy']['value']==.6
    assert result['reference_unknown_rate']['numerator']==21


def test_empty_and_undefined_metrics_are_null_with_exact_zero_denominators():
    result=analyze([])
    assert result['five_way_accuracy']['value'] is None and result['five_way_accuracy']['denominator']==0
    for category in result['per_class'].values():
        assert category['precision']['value'] is None and category['recall']['value'] is None
    rows=[dict(sample_id='only-unknown',reference='UNKNOWN',prediction='UNKNOWN',cluster='one',case='case',target='target')]
    result=analyze(rows)
    assert result['selective_accuracy']['value'] is None
    assert result['five_way_accuracy']['value']==1
    assert result['confirmed_violation']['false_positive_rate_verified_references']['value'] is None


def test_cohens_kappa_hand_calculation_and_degenerate_marginals():
    rows=[dict(sample_id=str(i),first=a,second=b,cluster=str(i)) for i,(a,b) in enumerate([
        ('CONFIRMED','CONFIRMED'),('CONFIRMED','BLOCKED'),('BLOCKED','CONFIRMED'),('BLOCKED','BLOCKED')])]
    result=agreement(rows)
    assert result['raw_agreement']['numerator']==2 and result['raw_agreement']['denominator']==4
    assert result['kappa']['value']==0 and result['kappa']['expected_agreement']==.5
    swapped=[dict(sample_id='a',first='CONFIRMED',second='BLOCKED',cluster='a'),
             dict(sample_id='b',first='BLOCKED',second='CONFIRMED',cluster='b')]
    assert agreement(swapped)['kappa']['value']==-1
    degenerate=agreement([dict(sample_id='one',first='UNKNOWN',second='UNKNOWN',cluster='one')])
    assert degenerate['raw_agreement']['value']==1 and degenerate['kappa']['value'] is None
    assert degenerate['kappa']['undefined_reason']
    assert agreement([])['kappa']['value'] is None


def test_whole_cluster_bootstrap_preserves_repeats_and_global_rng_state():
    rows=[]
    for group,prediction in [('a','CONFIRMED'),('b','BLOCKED')]:
        rows.extend(dict(sample_id=f'{group}-{i}',reference='CONFIRMED',prediction=prediction,
                         cluster=group,case=group,target=group) for i in range(20))
    spec=Bootstrap(seed=17,resamples=200,confidence=.95)
    before=random.getstate();first=analyze(rows,bootstrap=spec);second=analyze(rows,bootstrap=spec)
    assert first==second and random.getstate()==before
    interval=first['five_way_accuracy']['interval']
    assert interval['lower']==0 and interval['upper']==1 # two whole clusters, not 40 independent trials
    assert interval['valid_resamples']==200
    assert first['denominators']['paired_actions']==40
    assert first['denominators']['declared_clusters']==2
    for row in rows: row['cluster']='one-shared-cluster'
    one=analyze(rows,bootstrap=spec)
    assert one['five_way_accuracy']['interval']['lower'] is None
    assert 'fewer than two' in one['five_way_accuracy']['interval']['reason']


def test_bootstrap_reports_undefined_denominators_instead_of_silent_drops():
    result=analyze(pairs(),bootstrap=Bootstrap(seed=31,resamples=200,confidence=.9))
    interval=result['per_class']['ATTEMPTED']['precision']['interval']
    assert interval['lower'] is None and interval['reason']=='original denominator zero'
    interval=result['per_class']['CONFIRMED']['recall']['interval']
    assert interval['valid_resamples']+interval['undefined_resamples']==200
    assert interval['undefined_resamples']>0
    assert 'conditional' in interval['scope']


def test_agreement_resampling_retains_cluster_units():
    rows=[dict(sample_id='a',first='CONFIRMED',second='CONFIRMED',cluster='a'),
          dict(sample_id='b',first='BLOCKED',second='UNKNOWN',cluster='b')]
    spec=Bootstrap(seed=2,resamples=100,confidence=.95)
    first=agreement(rows,bootstrap=spec)
    assert first==agreement(rows,bootstrap=spec)
    assert first['kappa']['interval']['undefined_resamples']>0
    assert first['raw_agreement']['interval']['valid_resamples']==100


@pytest.mark.parametrize('changes',[{'seed':True},{'resamples':99},{'resamples':10001},
                                    {'confidence':0},{'confidence':1},{'confidence':float('nan')},{'method':'iid-action-bootstrap'}])
def test_invalid_resampling_contracts(changes):
    raw=dict(seed=1,resamples=100,confidence=.95);raw.update(changes)
    with pytest.raises(ValueError): Bootstrap(**raw)


@pytest.mark.parametrize('bad',['duplicate','category','cluster','provenance'])
def test_invalid_metric_inputs_fail(bad):
    rows=pairs()
    if bad=='duplicate': rows.append(deepcopy(rows[0]))
    if bad=='category': rows[0]['reference']='SUCCESS'
    if bad=='cluster': rows[0]['cluster']=''
    with pytest.raises(ValueError):
        analyze_pairs(rows,provenance='unverified-independent' if bad=='provenance' else 'synthetic_engineering_only')
