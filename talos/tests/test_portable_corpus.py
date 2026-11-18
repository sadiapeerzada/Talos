"""Passive synthetic dataset tests; no payload delivery or target execution."""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from talos.corpus import (
    CommonPool, Corpus, Surface, arm_inputs, check_leakage, content_hash,
    load_bindings, load_corpus, load_split, load_taxonomy, plan_case, public_opportunity,
)
from talos.corpus.models import AttackCase, CaseRecord, validate_identity_continuity
from talos.corpus.planning import BindingSet, FixtureBinding
from talos.corpus.splits import SplitManifest, normalized_text, schema_fingerprint
from talos.corpus.taxonomy import TaxonomyRegistry, validate_mappings
from talos.profiles import TargetProfile
from talos.targets.documents import DocumentDomain
from talos.targets.helpdesk import HelpdeskDomain
from talos.targets.profiles import target_profile


def profile(domain='it-helpdesk', variant='hardened'):
    # Passive metadata only: no ControlledEnvironment, store, reset or actions.
    return target_profile(HelpdeskDomain() if domain == 'it-helpdesk' else DocumentDomain(),
                          domain + '.test-instance', 'synthetic-profile-source', variant)


def record(case):
    case = AttackCase.model_validate(case.model_dump() if isinstance(case, AttackCase) else case)
    return CaseRecord(case=case, sha256=content_hash(case))


def mutate_case(**changes):
    raw = load_corpus().records[0].case.model_dump(mode='json')
    raw.update(changes)
    return raw


def bound(index=0, domain='it-helpdesk'):
    corpus, bindings = load_corpus(), load_bindings()
    rec = corpus.records[index]
    b = next(b for b in bindings.bindings if b.case_identity == rec.identity and b.domain == domain)
    return rec, profile(domain), b


def proposed_split(corpus, left='TP1-DIRECT', right='TP1-DIRECT-PARAPHRASE'):
    assignments = {r.case.case_id: 'UNASSIGNED' for r in corpus.records}
    assignments.update({left: 'DEV', right: 'TEST'})
    return SplitManifest(corpus_sha256=content_hash(corpus), assignments=assignments)


def contexts(bindings):
    return {b.binding_id: profile(b.domain) for b in bindings.bindings}


def test_package_integrity_and_roundtrip():
    corpus = load_corpus()
    assert len(corpus.records) == 12
    assert len(load_bindings().bindings) == 24
    assert Corpus.model_validate_json(corpus.model_dump_json()) == corpus
    assert content_hash(json.loads(corpus.model_dump_json())) == content_hash(corpus)
    validate_mappings(corpus, load_taxonomy())
    assert set(load_split().assignments.values()) == {'UNASSIGNED'}
    assert all(r.case.provenance.independent_validity == 'not_established' for r in corpus.records)
    assert all(r.case.provenance.review_status == 'unreviewed' for r in corpus.records)
    assert all(r.case.provenance.origin != 'independently_supplied' for r in corpus.records)


@pytest.mark.parametrize('field,value', [
    ('case_id','bad'), ('revision',0), ('revision',True), ('revision','1'),
    ('schema_version','talos.attack-case.v2'), ('corpus_version','Talos-35'),
    ('family','unrecognized'), ('entry_surface','web-whatever'), ('objective',''),
    ('intended_policy_boundary',''), ('prerequisites',[]), ('scenario_ancestry',[]),
    ('tool_requirements',[]), ('stimuli',[]), ('expected_observable_evidence',[]),
    ('expectations',[]), ('kind','measured_success'), ('parent_case_ids',['TP1-DIRECT']),
    ('public_parameter_names',['action_tool']), ('public_parameter_names',['x.y']),
    ('observed_outcome','CONFIRMED'), ('risk_score',100),
])
def test_invalid_cases_rejected(field,value):
    with pytest.raises((ValidationError, ValueError)):
        record(mutate_case(**{field:value}))


@pytest.mark.parametrize('text', ['{missing}', '{action_tool.name}', '{action_tool[0]}',
                                '{action_tool!r}', '{action_tool:>20}', '{', '{}'])
def test_unsafe_or_undeclared_template_fields(text):
    with pytest.raises(ValueError):
        record(mutate_case(stimuli=[{'surface':'user_message','text':text}]))


def test_literal_braces_are_preserved_once():
    rec,p,b = bound()
    c = rec.case.model_dump(mode='json')
    c['stimuli'][0]['text'] = '{{literal}} {requested_effect}'
    rec = record(c)
    raw = b.model_dump()
    raw['case_identity'] = rec.identity
    raw['public_parameters']['requested_effect'] = '{not_a_template}'
    b = FixtureBinding.model_validate(raw)
    result = plan_case(rec,p,b,available_surfaces=frozenset(Surface))
    assert result.stimuli[0].text == '{literal} {not_a_template}'
    assert public_opportunity(rec,p,b,result).stimuli == result.stimuli


@pytest.mark.parametrize('mode', ['duplicate', 'missing_parent', 'cycle', 'bad_hash', 'wrong_version'])
def test_corpus_identity_validation(mode):
    raw = load_corpus().model_dump(mode='json')
    if mode == 'duplicate':
        raw['records'].append(deepcopy(raw['records'][0]))
    elif mode == 'bad_hash':
        raw['records'][0]['sha256'] = '0'*64
    elif mode == 'wrong_version':
        raw['corpus_version'] = 'Talos-35'
    else:
        c = raw['records'][0]['case']
        c['parent_case_ids'] = ['TP1-NOT-HERE' if mode == 'missing_parent' else 'TP1-DIRECT-PARAPHRASE']
        raw['records'][0]['sha256'] = content_hash(c)
    with pytest.raises(ValueError):
        Corpus.model_validate(raw)


def test_revision_continuity():
    corpus = load_corpus()
    raw = corpus.model_dump(mode='json')
    raw['records'][0]['case']['objective'] = 'Changed content'
    raw['records'][0]['sha256'] = content_hash(raw['records'][0]['case'])
    changed = Corpus.model_validate(raw)
    with pytest.raises(ValueError):
        validate_identity_continuity(corpus,changed)
    raw['records'][0]['case']['revision'] = 2
    raw['records'][0]['sha256'] = content_hash(raw['records'][0]['case'])
    newer = Corpus.model_validate(raw)
    validate_identity_continuity(corpus,newer)
    with pytest.raises(ValueError):
        validate_identity_continuity(newer,corpus)


@pytest.mark.parametrize('change', ['source','edition','category','exact','duplicate'])
def test_invalid_crosswalks(change):
    corpus = load_corpus().model_dump(mode='json')
    entry = corpus['records'][0]['case']['mappings'][0]
    if change == 'source': entry['source_id'] = 'wrong'
    if change == 'edition': entry['edition'] = '2025'
    if change == 'category': entry['category_id'] = 'LLM99'
    if change == 'exact': entry.update(category_id='LLM03',relation='exact_mechanism')
    if change == 'duplicate': corpus['records'][0]['case']['mappings'].append(deepcopy(entry))
    corpus['records'][0]['sha256'] = content_hash(corpus['records'][0]['case'])
    with pytest.raises(ValueError):
        validate_mappings(Corpus.model_validate(corpus),load_taxonomy())


@pytest.mark.parametrize('bad', ['duplicate_source','unknown_source','duplicate_category'])
def test_taxonomy_registry_references(bad):
    raw=load_taxonomy().model_dump(mode='json')
    if bad == 'duplicate_source': raw['sources'].append(raw['sources'][0])
    if bad == 'unknown_source': raw['categories'][0]['source_id']='missing'
    if bad == 'duplicate_category': raw['categories'].append(raw['categories'][0])
    with pytest.raises(ValueError): TaxonomyRegistry.model_validate(raw)


@pytest.mark.parametrize('index',range(12))
@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
def test_cross_domain_passive_compatibility(index,domain):
    rec,p,b = bound(index,domain)
    assert plan_case(rec,p,b).status == 'UNKNOWN'
    result=plan_case(rec,p,b,available_surfaces=frozenset(Surface))
    assert result.status == 'APPLICABLE', result.reasons
    assert len(result.stimuli)==len(rec.case.stimuli)
    for stimulus in result.stimuli:
        assert '{action_tool}' not in stimulus.text
    other=profile(domain,'vulnerable')
    assert plan_case(rec,other,b,available_surfaces=frozenset(Surface)).stimuli == result.stimuli
    assert all(e.status=='declared_test_expectation_not_observed' for e in rec.case.expectations)


@pytest.mark.parametrize('mutation,expected', [
    ('permissions','UNKNOWN'),('conflict','UNKNOWN'),('missing_schema','UNKNOWN'),
    ('effects','UNKNOWN'),('missing_capability','UNKNOWN'), ('mismatch','INAPPLICABLE'),
    ('missing_tool','INAPPLICABLE'),
])
def test_profile_uncertainty_and_inapplicability(mutation,expected):
    rec,p,b=bound()
    raw=p.model_dump(mode='json')
    tool=next(t for t in raw['tools'] if t['name']==b.tool_bindings['action_tool'])
    if mutation=='permissions': tool['permissions']=[]
    if mutation=='conflict': tool['effects'].append({'effect':'read_only','evidence_ids':['implementation']})
    if mutation=='missing_schema': tool['input_schema']={}
    if mutation=='effects': tool['effects']=[]
    if mutation=='missing_capability': tool['audit_capability_ids']=[]
    if mutation=='mismatch': tool['effects']=[{'effect':'read_only','evidence_ids':['implementation']}]
    if mutation=='missing_tool':
        bd=b.model_dump(); bd['tool_bindings']['action_tool']='nonexistent'; b=FixtureBinding.model_validate(bd)
    p=TargetProfile.model_validate(raw)
    result=plan_case(rec,p,b,available_surfaces=frozenset(Surface))
    assert result.status==expected
    with pytest.raises(ValueError): public_opportunity(rec,p,b,result)


def test_renamed_tools_and_schema_properties():
    rec,p,b=bound()
    raw=p.model_dump(mode='json'); name=b.tool_bindings['action_tool']
    for t in raw['tools']:
        if t['name']==name:
            t['name']='opaque_729'
            t['description']='Opaque capability'
            t['input_schema']={'type':'object','properties':{'opaque':{'type':'string'}}}
    raw['possible_flows']=[]
    raw['target_id']='unfamiliar-target'
    p=TargetProfile.model_validate(raw)
    bd=b.model_dump(); bd['tool_bindings']['action_tool']='opaque_729'; b=FixtureBinding.model_validate(bd)
    result=plan_case(rec,p,b,available_surfaces=frozenset(Surface))
    assert result.status=='APPLICABLE'
    assert 'opaque_729' in result.stimuli[0].text
    assert name not in result.stimuli[0].text


def test_common_public_pool_has_no_observer_metadata():
    rec,p,b=bound()
    ready=plan_case(rec,p,b,available_surfaces=frozenset(Surface))
    opportunity=public_opportunity(rec,p,b,ready)
    payload=opportunity.model_dump_json()
    for private in ('expectations','admissible_outcomes','provenance','mappings','policy_assumption',
                    'family_id','audit_capabilities','authorization_boundaries','evidence_ids','TP1-DIRECT'):
        assert private not in payload
    pool=CommonPool(opportunities=(opportunity,))
    blind=arm_inputs(pool)
    aware=arm_inputs(pool,graph_annotations={'nodes':[], 'edges':[]})
    assert blind['opportunities']==aware['opportunities']
    assert blind['common_pool_sha256']==aware['common_pool_sha256']
    assert blind['graph_annotations'] is None
    with pytest.raises(ValueError): CommonPool(opportunities=(opportunity,opportunity))
    forged=ready.model_copy(update={'stimuli':()})
    with pytest.raises(ValueError): public_opportunity(rec,p,b,forged)


@pytest.mark.parametrize('mutation',['corpus','case','slots','parameters','duplicate'])
def test_binding_integrity(mutation):
    corpus=load_corpus(); raw=load_bindings().model_dump(mode='json')
    if mutation=='corpus': raw['corpus_sha256']='0'*64
    if mutation=='case': raw['bindings'][0]['case_identity']='bad'
    if mutation=='slots': raw['bindings'][0]['tool_bindings']={}
    if mutation=='parameters': raw['bindings'][0]['public_parameters']['private']='label'
    if mutation=='duplicate': raw['bindings'].append(raw['bindings'][0])
    with pytest.raises(ValueError): BindingSet.model_validate(raw).validate_against(corpus)


def test_no_approved_split_is_shipped():
    corpus,bs=load_corpus(),load_bindings()
    report=check_leakage(corpus,load_split(),bs,contexts(bs))
    assert not report.issues
    assert len(report.unassigned_case_ids)==12
    assert report.semantic_review_required and not report.approved_for_evaluation
    assert report.independent_validity=='not_established'


def test_declared_and_transitive_leakage_axes():
    corpus,bs=load_corpus(),load_bindings()
    report=check_leakage(corpus,proposed_split(corpus),bs,contexts(bs))
    axes={i.axis for i in report.issues}
    assert {'family','template','paraphrase','case_ancestry','scenario_ancestry','target_identity','tool_schema'} <= axes
    assert not report.approved_for_evaluation


@pytest.mark.parametrize('bad',['hash','missing','extra','profiles','split_name','approval','threshold'])
def test_split_invalid_or_incomplete_context(bad):
    corpus,bs=load_corpus(),load_bindings(); raw=load_split().model_dump(mode='json'); ps=contexts(bs)
    if bad=='hash': raw['corpus_sha256']='0'*64
    if bad=='missing': raw['assignments'].pop('TP1-DIRECT')
    if bad=='extra': raw['assignments']['not-a-case']='DEV'
    if bad=='profiles': ps.pop(next(iter(ps)))
    if bad=='split_name': raw['assignments']['TP1-DIRECT']='TRAIN'
    if bad=='approval': raw['review_status']='approved'
    with pytest.raises(ValueError):
        check_leakage(corpus,SplitManifest.model_validate(raw),bs,ps,similarity_threshold=2 if bad=='threshold' else .85)


def test_schema_and_text_renaming_leakage():
    a={'title':'A','type':'object','properties':{'employee_id':{'type':'string','description':'employee'}},'required':['employee_id']}
    b={'title':'B','type':'object','properties':{'opaque':{'type':'string','description':'opaque'}},'required':['opaque']}
    assert schema_fingerprint(a)==schema_fingerprint(b)
    b['required']=[]
    assert schema_fingerprint(a)!=schema_fingerprint(b)
    assert normalized_text(' ＡＢＣ, Action! ')==normalized_text('abc action')


def test_identical_normalized_payload_detected_across_distinct_declared_families():
    corpus=load_corpus(); raw=corpus.model_dump(mode='json')
    left=raw['records'][0]['case']; right=raw['records'][3]['case']
    right['stimuli']=deepcopy(left['stimuli'])
    raw['records'][3]['sha256']=content_hash(right)
    updated=Corpus.model_validate(raw)
    # Bindings require exact identity after any case revision/content change.
    bd=load_bindings().model_dump(mode='json'); bd['corpus_sha256']=content_hash(updated)
    old_id=corpus.records[3].identity; new_id=updated.records[3].identity
    for binding in bd['bindings']:
        if binding['case_identity']==old_id: binding['case_identity']=new_id
    bs=BindingSet.model_validate(bd)
    report=check_leakage(updated,proposed_split(updated,'TP1-DIRECT','TP1-AUTH-SPOOF'),bs,contexts(bs))
    assert 'text_similarity' in {i.axis for i in report.issues}


@pytest.mark.parametrize('failure',['manifest','taxonomy','case'])
def test_loader_rejects_tampered_package(monkeypatch,failure):
    import talos.corpus.loading as loader
    original=loader._data
    def altered(name):
        raw=original(name)
        if failure=='manifest' and name=='manifest.json': raw['corpus_sha256']='0'*64
        if failure=='taxonomy' and name=='taxonomy.json': raw['categories'][0]['title']='tampered'
        if failure=='case' and name=='cases.json': raw['records'][0]['case']['objective']='tampered'
        return raw
    monkeypatch.setattr(loader,'_data',altered)
    with pytest.raises(ValueError): loader.load_corpus()


def test_no_customer_service_dependencies_or_execution_imports():
    corpus_root=Path(__file__).parents[1]/'talos'/'corpus'
    for path in corpus_root.glob('*.py'):
        text=path.read_text()
        for forbidden in ('talos.sample_agents','talos.attacks','talos.targets','import anthropic',
                          'import httpx','talos.scan_service','talos.learning'):
            assert forbidden not in text


@pytest.mark.parametrize('domain',['it-helpdesk','document-management'])
def test_all_proposed_fixture_arguments_match_actual_schemas_without_execution(domain):
    tools={t.name:t for t in (HelpdeskDomain() if domain=='it-helpdesk' else DocumentDomain()).tools}
    for b in load_bindings().bindings:
        if b.domain==domain:
            for slot,name in b.tool_bindings.items():
                parsed=tools[name].arguments.model_validate(b.proposed_tool_arguments[slot])
                assert parsed.model_dump()==b.proposed_tool_arguments[slot]


@pytest.mark.parametrize('mutation', ['direct_surface','indirect_surface','workflow_step','control_attack',
                                     'derived_parent','review_reference','unknown_contract','unknown_role'])
def test_conditional_case_contracts(mutation):
    corpus=load_corpus()
    raw=corpus.records[0].case.model_dump(mode='json')
    if mutation=='direct_surface': raw['entry_surface']='tool_output'
    if mutation=='indirect_surface': raw['family']='indirect_prompt_injection'
    if mutation=='workflow_step': raw['family']='multi_step_workflow'
    if mutation=='control_attack': raw['family']='control'
    if mutation=='derived_parent': raw['provenance']['origin']='derived_synthetic'
    if mutation=='review_reference': raw['provenance']['review_status']='review_reference_supplied'
    if mutation=='unknown_contract':
        raw['kind']='unknown_evidence'; raw['expectations'][0]['admissible_outcomes']=['CONFIRMED']
    if mutation=='unknown_role': raw['tool_requirements'][0]['any_roles']=['unknown']
    with pytest.raises(ValueError): record(raw)


def test_trust_dependent_tool_output_requirement():
    rec,p,b=bound()
    raw=rec.case.model_dump(mode='json')
    raw['tool_requirements'][0]['needs_untrusted_output']=True
    rec=record(raw)
    bd=b.model_dump(); bd['case_identity']=rec.identity; b=FixtureBinding.model_validate(bd)
    assert plan_case(rec,p,b,available_surfaces=frozenset(Surface)).status=='INAPPLICABLE'


def test_tampered_model_instances_cannot_bypass_plan_validation():
    rec,p,b=bound()
    rec.case.stimuli[0].__dict__['text']='{undeclared}'
    with pytest.raises(ValueError): plan_case(rec,p,b,available_surfaces=frozenset(Surface))


def test_graph_projection_retains_possible_edges_without_private_evidence():
    from talos.graph.portable import build_profile_graph
    from talos.corpus.planning import project_possible_graph
    rec,p,b=bound()
    graph=build_profile_graph(p)
    graph.add_edge('tool:lookup_employee','tool:grant_access',relation='observed_call_order',
                   scope={'private':'run'},action_digests=['private-action'])
    projected=project_possible_graph(graph)
    raw=projected.model_dump_json()
    assert 'possible_invocation' in raw and 'possible_data_flow' in raw
    for private in ('scope','observed_call_order','private-action','evidence_ids','policy_id'):
        assert private not in raw
    pool=CommonPool(opportunities=(public_opportunity(rec,p,b,plan_case(rec,p,b,available_surfaces=frozenset(Surface))),))
    assert arm_inputs(pool,graph_annotations=projected)['common_pool_sha256']==pool.digest()


@pytest.mark.parametrize('graph', [
    {'nodes':[], 'edges':[], 'expectations':['CONFIRMED']},
    {'nodes':['tool:other'], 'edges':[]},
    {'nodes':['input:user'], 'edges':[{'source':'input:user','target':'input:user','relation':'observed_call_order'}]},
    {'nodes':[], 'edges':[{'source':'a','target':'b','relation':'possible_data_flow'}]},
])
def test_graph_arm_rejects_private_fields_unknown_inventory_and_observed_paths(graph):
    rec,p,b=bound()
    pool=CommonPool(opportunities=(public_opportunity(rec,p,b,plan_case(rec,p,b,available_surfaces=frozenset(Surface))),))
    with pytest.raises(ValueError): arm_inputs(pool,graph_annotations=graph)


def test_leakage_rejects_missing_case_target_context():
    corpus,bs=load_corpus(),load_bindings()
    raw=bs.model_dump()
    raw['bindings']=[b for b in raw['bindings'] if b['case_identity']!=corpus.records[0].identity]
    bs=BindingSet.model_validate(raw)
    with pytest.raises(ValueError): check_leakage(corpus,load_split(),bs,contexts(bs))


@pytest.mark.parametrize('resource',['bindings.json','split.json'])
def test_binding_and_split_content_are_manifest_pinned(monkeypatch,resource):
    import talos.corpus.loading as loader
    original=loader._data
    def altered(name):
        raw=original(name)
        if name==resource:
            if name=='bindings.json': raw['bindings'][0]['proposed_actor_id']='impostor'
            else: raw['assignments']['TP1-DIRECT']='TEST'
        return raw
    monkeypatch.setattr(loader,'_data',altered)
    with pytest.raises(ValueError): loader.load_corpus()
