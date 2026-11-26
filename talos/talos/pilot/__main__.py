"""Readiness/schema only; deliberately no pilot/run/inference command."""
import argparse,json
from talos.pilot import ModelPlan,Scope,BenignPlan,BenignScope,CompatibilityPlan,CompatibilityScope
from talos.pilot.compatibility import CompatibilityApproval,CompatibilityRegistry


def readiness():
    return {'schema_version':'talos.DEV-pilot-preparation.v1','stage':'PR09_B1','inference_enabled':False,
        'pilot_authorized':False,'pilot_executed':False,'pr09_experimental_complete':False,'engineering':'REVIEW_REQUIRED',
        'empirical_execution':'NO-GO','trust_root':'NOT_SUPPLIED','approvals':'NOT_SUPPLIED','model_selection':{'checkpoint':'mlx-community/Qwen3-4B-Instruct-2507-4bit','revision':'50d427756c6b1b2fe0c0a10f67fbda1fc8e82c1b','runtime':'MLX-LM','role':'defender_target_agent_not_attacker','status':'PROPOSED_NOT_APPROVED'},
        'budget_approval':None,'owned_server_custody':None,'containment_review':None,'independent_review':None,
        'test_cohort':'UNASSIGNED','primary':'A2-A1','proposed_secondary':'A4-A1_PENDING_APPROVAL'}


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=('readiness','schema'));a=p.parse_args()
    print(json.dumps(readiness() if a.command=='readiness' else {'plan':ModelPlan.model_json_schema(),'approval_scope':Scope.model_json_schema(),
        'benign_plan':BenignPlan.model_json_schema(),'benign_approval_scope':BenignScope.model_json_schema(),
        'compatibility_plan':CompatibilityPlan.model_json_schema(),'compatibility_scope':CompatibilityScope.model_json_schema(),
        'compatibility_registry':CompatibilityRegistry.model_json_schema(),'compatibility_approval':CompatibilityApproval.model_json_schema()},sort_keys=True,indent=2))


if __name__=='__main__':main()
