"""Strict offline package loading and manifest integrity."""
import json
from importlib.resources import files
from talos.corpus.models import Corpus, content_hash
from talos.corpus.planning import BindingSet
from talos.corpus.splits import SplitManifest
from talos.corpus.taxonomy import TaxonomyRegistry, validate_mappings


def _data(name):
    return json.loads(files("talos.corpus").joinpath("data", name).read_text(encoding="utf-8"))


def load_taxonomy() -> TaxonomyRegistry:
    return TaxonomyRegistry.model_validate(_data("taxonomy.json"))


def load_corpus() -> Corpus:
    corpus = Corpus.model_validate(_data("cases.json"))
    manifest = _data("manifest.json")
    registry = load_taxonomy()
    if manifest != {"schema_version": "talos.corpus-manifest.v1", "corpus_version": corpus.corpus_version,
                    "corpus_sha256": content_hash(corpus), "taxonomy_sha256": content_hash(registry),
                    "case_hashes": {r.case.case_id: r.sha256 for r in corpus.records},
                    "bindings_sha256": content_hash(_data("bindings.json")),
                    "split_sha256": content_hash(_data("split.json"))}:
        raise ValueError("corpus manifest mismatch")
    validate_mappings(corpus, registry)
    return corpus


def load_bindings() -> BindingSet:
    bindings = BindingSet.model_validate(_data("bindings.json"))
    bindings.validate_against(load_corpus())
    return bindings


def load_split() -> SplitManifest:
    split = SplitManifest.model_validate(_data("split.json"))
    corpus = load_corpus()
    if split.corpus_sha256 != content_hash(corpus) or set(split.assignments) != {r.case.case_id for r in corpus.records}:
        raise ValueError("split manifest mismatch")
    return split
