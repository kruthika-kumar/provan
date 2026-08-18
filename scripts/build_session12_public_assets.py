from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).parents[1]))
from provan.canonical import canonical_bytes, sha256_bytes
from provan.foundry import PATTERN_FAMILIES, PROVIDERS, PUBLIC_PROMPTS, pattern_library
from provan.modeling import FROZEN_PUBLIC_MODEL_EGRESS
from provan.session12_validators import validate_pattern_library_serialized


ROOT=Path(__file__).parents[1];OUT=ROOT/"artifacts"/"session12"/"public"


def main()->int:
    OUT.mkdir(parents=True,exist_ok=True)
    library=pattern_library();raw=canonical_bytes(library);validate_pattern_library_serialized(raw);(OUT/"verification_pattern_library.v1.public.json").write_bytes(raw)
    prompts={"schema_id":"provan.foundry_role_prompt_registry.v1","sensitivity":"PUBLIC_SAFE","registry_id":"community.foundry-roles.v1","version":1,"prompts":[{"role":role,"version":1,"template":template,"sha256":sha256_bytes(template.encode("utf-8"))} for role,template in sorted(PUBLIC_PROMPTS.items())],"stateless":True,"persistent_conversation":False,"background":False}
    (OUT/"role_prompt_registry.v1.public.json").write_bytes(canonical_bytes(prompts))
    policy={"schema_id":"provan.foundry_routing_policy.v1","sensitivity":"PUBLIC_SAFE","policy_id":"community.foundry-router.v1","version":1,"tiers":[{"tier":0,"roles":[]},{"tier":1,"roles":["semantic_interpreter"]},{"tier":2,"roles":["strong_reasoner"]},{"tier":3,"roles":["strong_reasoner","independent_critic"]}],"unresolved_inputs":"ESCALATE","model_may_change_inputs":False,"configured_provider":{"provider_id":"openai-responses-primary",**PROVIDERS["openai-responses-primary"],"availability_endpoint_use":"VALIDATION_ONLY_NOT_SELECTION"},"scripted_provider":{"testing_only":True,"semantic_qualification":False}}
    (OUT/"routing_policy.v1.public.json").write_bytes(canonical_bytes(policy))
    egress={"schema_id":"provan.foundry_model_egress_allowlist.v1","sensitivity":"PUBLIC_SAFE","provider":"openai-responses-primary","origin":"https://api.openai.com","model":"gpt-5.2","cases":[{"case_id":case_id,"selected_source_digests":list(digests)} for case_id,digests in sorted(FROZEN_PUBLIC_MODEL_EGRESS.items())],"arbitrary_manifest_egress":False,"operator_confirmation_required":True,"store_requested":False,"provider_retention":"PROVIDER_RETENTION_NOT_ZERO_OR_ESTABLISHED"}
    (OUT/"model_egress_allowlist.v1.public.json").write_bytes(canonical_bytes(egress))
    print(sha256_bytes(raw),len(PATTERN_FAMILIES));return 0


if __name__=="__main__":raise SystemExit(main())
