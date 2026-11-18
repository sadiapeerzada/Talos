"""Pinned primary-source crosswalk, separate from verdicts."""
from datetime import date
from typing import Literal
from pydantic import Field, model_validator
from talos.corpus.models import Corpus, Family, Model


class Source(Model):
    source_id: str = Field(min_length=1)
    publisher: str = Field(min_length=1)
    url: str = Field(pattern=r"^https://")
    retrieved_on: date
    version_reference: str = Field(min_length=1)
    retrieval_note: str = Field(min_length=1)


class Category(Model):
    system: str
    edition: str
    category_id: str
    title: str
    source_id: str
    locator: str = Field(min_length=1)
    exact_families: tuple[Family, ...] = ()


class TaxonomyRegistry(Model):
    schema_version: Literal["talos.crosswalk.v1"] = "talos.crosswalk.v1"
    sources: tuple[Source, ...] = Field(min_length=1)
    categories: tuple[Category, ...] = Field(min_length=1)
    coverage_exclusions: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def references(self):
        sources = {s.source_id for s in self.sources}
        keys = {(c.system, c.edition, c.category_id) for c in self.categories}
        if len(sources) != len(self.sources) or len(keys) != len(self.categories):
            raise ValueError("duplicate source or category")
        if any(c.source_id not in sources for c in self.categories):
            raise ValueError("unknown taxonomy source")
        return self


def validate_mappings(corpus: Corpus, registry: TaxonomyRegistry):
    categories = {(c.system, c.edition, c.category_id): c for c in registry.categories}
    for record in corpus.records:
        seen = set()
        for mapping in record.case.mappings:
            key = (mapping.system, mapping.edition, mapping.category_id)
            if key not in categories or key in seen:
                raise ValueError("unknown edition/category or duplicate mapping")
            seen.add(key)
            category = categories[key]
            if mapping.source_id != category.source_id:
                raise ValueError("taxonomy attribution mismatch")
            if mapping.relation == "exact_mechanism" and record.case.family not in category.exact_families:
                raise ValueError("unsupported exact mapping")
