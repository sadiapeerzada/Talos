# Stage B1 continuation: proposed Qwen/MLX defender

2026-11-20. Continues `research/pr-09-b1-pilot-preparation` from `6310be9629a235c414eb55ee4103d65fc26991da`. Original PR #25 was already merged. The user authorized pushing this continuation to the same branch and supplying a compare link, **not another PR**. No PR-09 B2, pilot, TEST freeze, PR-10 or publication work.

**Engineering GO for review of the refinement; operational DEV pilot remains NO-GO.** Model selection and numerical ceilings are proposed, not approved. All previous genuine authority, policy/evidence custody, independent review, case/surface approval, worker/egress containment and separate DEV GO requirements remain.

## Exact candidate and proposed limits

| Item | Proposed value / source identity |
| --- | --- |
| Model role | Defender/target agent; not an attacker model |
| Upstream | `Qwen/Qwen3-4B-Instruct-2507` |
| Quantized checkpoint | `mlx-community/Qwen3-4B-Instruct-2507-4bit` |
| Checkpoint revision | `50d427756c6b1b2fe0c0a10f67fbda1fc8e82c1b` |
| Runtime | MLX-LM 0.26.2, MLX 0.26.2; source-compatible proposal for Apple Silicon |
| Tokenizer library | Transformers 4.53.3; NumPy 2.3.2; complete separate hash lock for CPython 3.13/macOS arm64 |
| Context | 4,096 total tokens; reject prompt >3,584 when reserving all 512 output tokens |
| Maximum output | 512 tokens per request |
| Sampling | Temperature 0; no seed or deterministic-generation guarantee |
| Episodes / requests | At most 8 episodes, at most 4 model requests each, at most 32 total attempts |
| Total wall time | At most 1,800,000 ms (30 minutes), shared across episodes/arms |
| Paid API spending | ₹0; local hardware/energy cost stays unknown, not zero |
| Approved settings / execution | None; inference disabled and pilot not executed |

The [machine decision packet](pr09b1_decision_packet.json), [candidate pin](../../talos/talos/pilot/qwen_mlx_candidate.json) and [runtime lock](../../talos/requirements-mlx-candidate.lock) preserve exact identifiers. No DEV family, cohort, reviewer identity, approved budget or target custody was selected automatically.

## Metadata custody without model download

Only the Hugging Face repository metadata response and five small pinned files were fetched: config, generation config, tokenizer **configuration**, chat template and model card. No safetensors, tokenizer.json, vocab or merge assets were downloaded. No MLX package was installed/imported, no model loaded and no inference/real model request executed. Dependency resolution fetched package metadata only; ordinary offline tests ran in a separate existing-research/verifier environment.

- Published weight SHA-256 from LFS metadata: `2a73c6c248601ab904e035548abd8e6abb65ea27dcb5f342fb0a8910eb44173f` (2,263,022,417 bytes). This is **not** a locally verified weight digest.
- Config SHA-256 from the fetched 938-byte file: `574349e5a343236546fda55e4744a76e181f534182d7dc60ff1bad7e7a502849`.
- Chat-template SHA-256 from the fetched 4,040-byte file: `40c21f34cf67d8c760ef72f8ad3ae5afad514299d4b06e91dd9a8d705af7b541`.

Small-file bytes were checked against the repository's Git blob SHA-1 identities. Non-fetched assets retain published LFS SHA-256 or Git-blob identities and exact sizes, with digest source and download flags. A future approved worker must hash the actual immutable local files; a repository ID or mutable main reference cannot replace that verification. Missing/local-symlinked/unexpected assets fail closed; there is no Hub download fallback or remote-code trust.

## MLX-specific implementation

`MLXModel` is a new union member; legacy LocalModel serialization and old B1 archive contracts remain intact. The native adapter has its own explicit version. The generic HTTP/llama-family adapter remains for compatibility and is not the selected candidate.

Pinned source inspection found that the 0.26.2 HTTP server emits null tool-call IDs and maintains a prompt cache. The selected design instead uses isolated per-request `stream_generate` with explicit public history/tools and no shared prompt cache, draft model or adapter weights. Future runtime imports/load occur only after real approval verification, local artifact hashes and exact runtime versions. The request child denies all networking and process spawning. No endpoint or API key can activate it.

The pinned tokenizer/template renders the known PR-03 schemas. Input is tokenized exactly before generation; overflow is rejected, not truncated. Qwen `<tool_call>` JSON is parsed without eval, with duplicate keys, unsupported markup, unknown tools, invalid argument schemas and malformed/incomplete calls rejected. Correlation IDs are **adapter-issued**, request-scoped identifiers, not invented claims that the model generated an ID. The original native text and native usage are retained. Termination/finality and exact integer prompt/generation counts are required; no character/word token estimates.

Both synthetic domains, operator-bound actors/resets, real local tool transitions, insertion/consumption receipts and private PR-01/05 packets use the existing Stage A control path. PR-07 graph/feedback visibility remains unchanged; the target model receives no graph, private policy, audit, oracle or reviewer inputs. Native normalization and the shared parser are independently rechecked during recorded-only replay. No native/model text establishes independent primary eligibility.

## Budgets, missingness and cancellation

One shared batch ledger covers all proposed episodes and arm identities. For genuine operation it must be a uniquely created, exclusively owned durable journal whose initial identity/path is included in signed budget evidence. It cannot silently reset or resume. The conservative 30-minute window currently starts at ledger construction and includes preparation/approval wait; changing that definition requires explicit review rather than a silent clock reset.

Each model-request attempt is debited before spawning, including failed/timeout attempts. Missing/invalid final usage halts the entire batch. Valid native token counts remain charged even when tool parsing fails; unavailable counts stay unknown and halt later calls. The ₹0 limit measures paid API spending only; no API exists in the native path, while hardware/energy spend remains null. Real pricing/custody/limits approval is still required—proposal data does not mint authority.

The parent enforces the lesser of request, conversation, arm and remaining batch time, kills/reaps its owned request process group on timeout/cancellation, and prevents cancellation-before-spawn races. Scheduling/cleanup overhead is recorded. A genuine pilot still requires reviewed supervision of the agent coordinator and OS egress/cancellation/finality evidence. Application controls are not an OS sandbox. No real MLX process or positive authorized deployment has been tested in this task; model/tool fidelity, hardware behavior and runtime execution compatibility remain unverified.

## Offline verification

**1,052 tests passed**, one existing Starlette/httpx deprecation warning, locally; this includes all prior 991 controls and 61 new MLX mocks. Focused B1/MLX subset: **153 passed**. Tests cover exact pins and role, context reservation, malformed/unsupported native tool text, missing/invalid usage/finality, both domains/variants and all supported surfaces, private oracle isolation, durable/shared caps, timeout/reaping/cancellation-before-spawn, missing authority, no MLX import, and native/normalized replay inconsistencies. Cancellation uses a real **non-model sleep process**, never inference.

Existing B1 CI now includes the MLX mock file. Hosted results/compare link are reported after the same-branch push. The old merged PR's 991-test result remains its historical result; it is not rewritten as validation of this continuation. No synthetic-only result is presented as a genuine DEV pilot or superiority finding.

## Primary sources and limits

- [Checkpoint at the pinned revision](https://huggingface.co/mlx-community/Qwen3-4B-Instruct-2507-4bit/tree/50d427756c6b1b2fe0c0a10f67fbda1fc8e82c1b) and [repository metadata API](https://huggingface.co/api/models/mlx-community/Qwen3-4B-Instruct-2507-4bit?blobs=true).
- [MLX-LM 0.26.2 generation API](https://github.com/ml-explore/mlx-lm/blob/v0.26.2/mlx_lm/generate.py), [local loader](https://github.com/ml-explore/mlx-lm/blob/v0.26.2/mlx_lm/utils.py), [Qwen3 model](https://github.com/ml-explore/mlx-lm/blob/v0.26.2/mlx_lm/models/qwen3.py), [tokenizer wrapper](https://github.com/ml-explore/mlx-lm/blob/v0.26.2/mlx_lm/tokenizer_utils.py), [sampler](https://github.com/ml-explore/mlx-lm/blob/v0.26.2/mlx_lm/sample_utils.py).
- Official package metadata for [MLX-LM 0.26.2](https://pypi.org/pypi/mlx-lm/0.26.2/json), [MLX 0.26.2](https://pypi.org/pypi/mlx/0.26.2/json), [Transformers 4.53.3](https://pypi.org/pypi/transformers/4.53.3/json).

These establish source/declared-dependency compatibility and content identity, not executed model compatibility, independent target validity, authority or study approval. Real approvals, provisioned immutable assets, hardware/runtime custody and independently checked evidence remain prerequisites. **Operational NO-GO; stop after Stage B1 for review.**
