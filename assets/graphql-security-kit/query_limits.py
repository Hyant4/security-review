"""Structural GraphQL query limits using graphql-core.

This is a first layer, not a schema-aware cost analyzer. Copy and adapt it to
the target GraphQL framework before parsing/executing untrusted operations.
"""

from __future__ import annotations

from dataclasses import dataclass

from graphql import GraphQLError, parse
from graphql.language.ast import (
    DocumentNode,
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    OperationDefinitionNode,
    SelectionSetNode,
)


class QueryLimitError(ValueError):
    pass


@dataclass(frozen=True)
class QueryLimits:
    max_bytes: int = 20_000
    max_tokens: int = 5_000
    max_operations: int = 1
    max_fragments: int = 50
    max_variables: int = 50
    max_depth: int = 12
    max_fields: int = 200
    max_aliases: int = 20
    max_expanded_selections: int = 1_000
    allow_introspection: bool = True

    def __post_init__(self) -> None:
        for name in (
            "max_bytes",
            "max_tokens",
            "max_operations",
            "max_depth",
            "max_fields",
            "max_aliases",
            "max_variables",
            "max_expanded_selections",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value < 1:
                raise ValueError(f"{name} must be positive")
        if isinstance(self.max_fragments, bool) or not isinstance(self.max_fragments, int):
            raise TypeError("max_fragments must be an integer")
        if self.max_fragments < 0:
            raise ValueError("max_fragments cannot be negative")
        if not isinstance(self.allow_introspection, bool):
            raise TypeError("allow_introspection must be a boolean")


@dataclass(frozen=True)
class QueryMetrics:
    operations: int
    fragments: int
    variables: int
    max_depth: int
    fields: int
    aliases: int
    expanded_selections: int
    uses_introspection: bool


@dataclass(frozen=True)
class _SelectionMetrics:
    depth_span: int = 0
    fields: int = 0
    aliases: int = 0
    expanded_selections: int = 0
    uses_introspection: bool = False


def _checked_add(current: int, addition: int, maximum: int, message: str) -> int:
    if addition > maximum - current:
        raise QueryLimitError(message)
    return current + addition


def measure(document: DocumentNode, limits: QueryLimits) -> QueryMetrics:
    """Measure and enforce a parsed document using bounded, memoized traversal."""
    if not isinstance(limits, QueryLimits):
        raise TypeError("limits must be a QueryLimits instance")

    fragment_definitions = [
        definition
        for definition in document.definitions
        if isinstance(definition, FragmentDefinitionNode)
    ]
    operations = [
        definition
        for definition in document.definitions
        if isinstance(definition, OperationDefinitionNode)
    ]
    if not operations:
        raise QueryLimitError("document has no executable operation")
    if len(operations) > limits.max_operations:
        raise QueryLimitError("too many operations")
    if len(fragment_definitions) > limits.max_fragments:
        raise QueryLimitError("too many fragments")

    fragments: dict[str, FragmentDefinitionNode] = {}
    for definition in fragment_definitions:
        name = definition.name.value
        if name in fragments:
            raise QueryLimitError(f"duplicate fragment definition: {name}")
        fragments[name] = definition

    variables = sum(len(operation.variable_definitions or ()) for operation in operations)
    if variables > limits.max_variables:
        raise QueryLimitError("too many variables")

    cache: dict[str, _SelectionMetrics] = {}
    visiting: set[str] = set()

    def selection_metrics(selection_set: SelectionSetNode) -> _SelectionMetrics:
        depth_span = fields = aliases = expanded = 0
        introspection = False
        for selection in selection_set.selections:
            expanded = _checked_add(
                expanded,
                1,
                limits.max_expanded_selections,
                "query exceeds expanded selection limit",
            )
            child = _SelectionMetrics()
            if isinstance(selection, FieldNode):
                fields = _checked_add(
                    fields, 1, limits.max_fields, "query exceeds field limit"
                )
                if selection.alias is not None:
                    aliases = _checked_add(
                        aliases, 1, limits.max_aliases, "query exceeds alias limit"
                    )
                introspection = introspection or selection.name.value.startswith("__")
                if introspection and not limits.allow_introspection:
                    raise QueryLimitError("introspection is disabled")
                if selection.selection_set is not None:
                    child = selection_metrics(selection.selection_set)
                    depth_span = max(depth_span, 1 + child.depth_span)
            elif isinstance(selection, InlineFragmentNode):
                child = selection_metrics(selection.selection_set)
                depth_span = max(depth_span, child.depth_span)
            elif isinstance(selection, FragmentSpreadNode):
                name = selection.name.value
                fragment = fragments.get(name)
                if fragment is None:
                    raise QueryLimitError(f"undefined fragment spread: {name}")
                child = fragment_metrics(name, fragment)
                depth_span = max(depth_span, child.depth_span)

            fields = _checked_add(
                fields, child.fields, limits.max_fields, "query exceeds field limit"
            )
            aliases = _checked_add(
                aliases, child.aliases, limits.max_aliases, "query exceeds alias limit"
            )
            expanded = _checked_add(
                expanded,
                child.expanded_selections,
                limits.max_expanded_selections,
                "query exceeds expanded selection limit",
            )
            introspection = introspection or child.uses_introspection
        return _SelectionMetrics(depth_span, fields, aliases, expanded, introspection)

    def fragment_metrics(
        name: str, fragment: FragmentDefinitionNode
    ) -> _SelectionMetrics:
        if name in cache:
            return cache[name]
        if name in visiting:
            raise QueryLimitError(f"cyclic fragment spread: {name}")
        visiting.add(name)
        try:
            result = selection_metrics(fragment.selection_set)
        finally:
            visiting.remove(name)
        cache[name] = result
        return result

    # Validate every fragment, including unused definitions, exactly once.
    for name, fragment in fragments.items():
        fragment_metrics(name, fragment)

    max_depth = fields = aliases = expanded = 0
    introspection = False
    for operation in operations:
        current = selection_metrics(operation.selection_set)
        operation_depth = 1 + current.depth_span
        if operation_depth > limits.max_depth:
            raise QueryLimitError("query exceeds depth limit")
        max_depth = max(max_depth, operation_depth)
        fields = _checked_add(
            fields, current.fields, limits.max_fields, "query exceeds field limit"
        )
        aliases = _checked_add(
            aliases, current.aliases, limits.max_aliases, "query exceeds alias limit"
        )
        expanded = _checked_add(
            expanded,
            current.expanded_selections,
            limits.max_expanded_selections,
            "query exceeds expanded selection limit",
        )
        introspection = introspection or current.uses_introspection

    return QueryMetrics(
        len(operations),
        len(fragment_definitions),
        variables,
        max_depth,
        fields,
        aliases,
        expanded,
        introspection,
    )


def parse_and_check_limits(
    query: str | bytes,
    limits: QueryLimits = QueryLimits(),
) -> tuple[DocumentNode, QueryMetrics]:
    """Parse once and return the document for subsequent schema validation."""
    if not isinstance(limits, QueryLimits):
        raise TypeError("limits must be a QueryLimits instance")
    if isinstance(query, str):
        raw = query.encode("utf-8")
    elif isinstance(query, bytes):
        raw = query
    else:
        raise TypeError("query must be str or bytes")
    if len(raw) > limits.max_bytes:
        raise QueryLimitError("query exceeds byte limit")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QueryLimitError("query is not valid UTF-8") from exc
    try:
        document = parse(decoded, max_tokens=limits.max_tokens)
        metrics = measure(document, limits)
    except (GraphQLError, RecursionError) as exc:
        raise QueryLimitError("invalid or excessively nested GraphQL document") from exc
    return document, metrics


def validate_query(query: str | bytes, limits: QueryLimits = QueryLimits()) -> QueryMetrics:
    """Compatibility helper for callers that only need structural metrics."""
    return parse_and_check_limits(query, limits)[1]
