# PR-09 B1 adapter, provenance and validation limits

2026-11-20 refinement: [Qwen/MLX candidate](pr09b1_mlx_refinement.md) is now selected for proposed defender use. The HTTP path below is retained for compatibility; MLX uses a separate versioned spec, metadata pin, native parser and isolated request worker. Candidate selection is not deployment approval.

`talos.pilot` prepares version `talos.local-chat-adapter.v1`. No inference command, model download/startup, default trust root, signing helper or credentials are supplied. The CLI prints readiness/schema only. Default LocalModelBackend cannot create an HTTP client without actual verified records and owned process/containment checks. ProtocolReplayBackend has no callable transport; it consumes fixed, explicitly labeled software JSON fixtures.

## Integration and source provenance

Stage A `readiness.agent.control` adds an explicit backend hook. The default still validates the original EngineeringPlan and executes its original script, retaining all prior behavior and records. A supplied known backend instead uses the versioned ModelPlan and bounded turns, validates messages/tool responses, reserves and settles model usage, and checks authority/deadline before tools. Direct, tool-output and document delivery reuse the same real synthetic stores, actor/reset binding, independently read policy/state and PR-01/05 packets. Model-generated indirect call IDs are resolved from an approved semantic ordinal, never invented. No private packet reaches the backend.

PR-07 PublicFeedback retains v1 defaults and gains an explicit v2 source for ordinary local-model responses, with version/source mismatch rejection. The existing Strategy consumes either through the same public tool-mention update rule. FourArmBridge shares the exact public pool, exposes topology only in aware views, keeps per-arm budgets separate and persistent, retains unsupported opportunities and forwards only ordinary terminal text. It never scores from oracle verdicts. The bridge does not create a new optimal selector or prove fairness/attack efficacy.

Protocol code validates single-choice nonstreaming function calls, exact model label, JSON object arguments (duplicate/nonfinite values rejected), tool schemas, IDs, finish reason and complete integer token counts. Context/output reservations are conservative, tied to the signed deployment context; actual server behavior is still unvalidated. Raw receipts, normalized token/debit details and private outcome packets are separately recorded. Actual costs and provider-internal retries remain null. No normalized security result is promoted above UNKNOWN/primary-null by the model output.

Recorded-only replay checks sealed manifest/intent/result/summary, conversion identity, full public history/tool schema/ordinary output/injection, action/reset bindings, unchanged private oracle replay and token/debit/count ledgers. Content hashes are not independent validity or signatures. A malformed/interrupted receipt is missing evidence, never a clean result. Per-attempt evidence capture is checkpointed at the completed result; a killed worker may lack partial evidence and must remain incomplete/UNKNOWN, not resumed implicitly.

## Primary references (checked 2026-11-19)

- [llama.cpp official server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md): local chat-completions/function-call interface, template/context configuration and reported usage. This is an assessed interface family, **not a selected or validated binary revision**. The server's alias does not establish weight identity; deployment hashes/custody are separate requirements.
- [cryptography Ed25519 verification API](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/ed25519/): optional verifier is pinned to `cryptography==50.0.2` and hash-locked separately. Existing Talos dependency locks are unchanged.
- [Official package metadata](https://pypi.org/project/cryptography/50.0.2/): version/dependency identity. The separate lock was generated with uv 0.11.29 against Python 3.11; CI tests actual pinned imports on 3.11/3.12.
- [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.txt): public verification test vector used by `crypto_smoke`. No private vector key is copied, no key/signature is generated, and the public vector is never an authority or approval.

The protocol does not assert compatibility with all OpenAI-compatible servers, a specific model's tool-call fidelity, template behavior, accurate internal billing or seed determinism. These must be checked in the genuinely authorized deployment. The operator's independent root authentication and reviewer independence declarations cannot be established merely by JSON/signature parsing.

## Reproduction without inference

Use a new environment; never install into the preserved user checkout/environment:

```sh
python -m venv /tmp/talos-b1-checks
/tmp/talos-b1-checks/bin/python -m pip install --require-hashes -r talos/requirements-research.lock -r talos/requirements-pilot.lock
PYTHONPATH=talos /tmp/talos-b1-checks/bin/python -m talos.pilot.crypto_smoke
PYTHONPATH=talos /tmp/talos-b1-checks/bin/python -m talos.pilot readiness
PYTHONPATH=talos/tests/offline_support:talos /tmp/talos-b1-checks/bin/python -m pytest talos/tests/ -v
```

The full command removes provider keys/proxies and uses the existing offline guard in local validation. Existing workflows still exercise legacy, full research, Stage A and native PyRIT controls; a new B1 matrix installs the optional pinned verifier and runs the RFC/public protocol tests. Software fixtures exercise conversion and local synthetic effects, not LLM inference, independent outcome validation or an empirical superiority result. There are no valid supplied approval bundles, so the authorized positive live path is deliberately untested and must not be reported as ready/approved.
