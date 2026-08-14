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
    max_operations: int = 1
    max_fragments: int = 50
    max_variables: int = 50
    max_depth: int = 12
    max_fields: int = 200
    max_aliases: int = 20
    allow_introspection: bool = True

    def __post_init__(self) -> None:
        for name in (
            "max_bytes", "max_operations", "max_depth", "max_fields",
            "max_aliases", "max_variables",
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
    uses_introspection: bool


def measure(document: DocumentNode, limits: QueryLimits | None = None) -> QueryMetrics:
    fragments = {
        definition.name.value: definition
        for definition in document.definitions
        if isinstance(definition, FragmentDefinitionNode)
    }
    operations = [
        definition
        for definition in document.definitions
        if isinstance(definition, OperationDefinitionNode)
    ]
    max_depth = fields = aliases = 0
    introspection = False
    for operation in operations:
        pending: list[tuple[SelectionSetNode, int, frozenset[str]]] = [
            (operation.selection_set, 1, frozenset())
        ]
        while pending:
            selection_set, depth, fragment_stack = pending.pop()
            max_depth = max(max_depth, depth)
            if limits and max_depth > limits.max_depth:
                raise QueryLimitError("query exceeds depth limit")
            for selection in selection_set.selections:
                if isinstance(selection, FieldNode):
                    fields += 1
                    aliases += int(selection.alias is not None)
                    introspection = introspection or selection.name.value.startswith("__")
                    if limits and fields > limits.max_fields:
                        raise QueryLimitError("query exceeds field limit")
                    if limits and aliases > limits.max_aliases:
                        raise QueryLimitError("query exceeds alias limit")
                    if limits and introspection and not limits.allow_introspection:
                        raise QueryLimitError("introspection is disabled")
                    if selection.selection_set:
                        pending.append((selection.selection_set, depth + 1, fragment_stack))
                elif isinstance(selection, InlineFragmentNode):
                    pending.append((selection.selection_set, depth, fragment_stack))
                elif isinstance(selection, FragmentSpreadNode):
                    name = selection.name.value
                    if name in fragment_stack:
                        raise QueryLimitError(f"cyclic fragment spread: {name}")
                    fragment = fragments.get(name)
                    if fragment is not None:
                        pending.append((fragment.selection_set, depth, fragment_stack | {name}))
    variables = sum(len(operation.variable_definitions or ()) for operation in operations)
    return QueryMetrics(
        len(operations), len(fragments), variables, max_depth, fields, aliases, introspection
    )


def parse_and_check_limits(
    query: str | bytes,
    limits: QueryLimits = QueryLimits(),
) -> tuple[DocumentNode, QueryMetrics]:
    """Parse once and return the document for subsequent schema validation."""
    raw = query if isinstance(query, bytes) else query.encode("utf-8")
    if len(raw) > limits.max_bytes:
        raise QueryLimitError("query exceeds byte limit")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QueryLimitError("query is not valid UTF-8") from exc
    try:
        document = parse(decoded)
    except (GraphQLError, RecursionError) as exc:
        raise QueryLimitError("invalid GraphQL document") from exc
    operation_count = sum(isinstance(item, OperationDefinitionNode) for item in document.definitions)
    fragment_count = sum(isinstance(item, FragmentDefinitionNode) for item in document.definitions)
    if operation_count == 0:
        raise QueryLimitError("document has no executable operation")
    if operation_count > limits.max_operations:
        raise QueryLimitError("too many operations")
    if fragment_count > limits.max_fragments:
        raise QueryLimitError("too many fragments")
    metrics = measure(document, limits)
    checks = (
        (metrics.operations > limits.max_operations, "too many operations"),
        (metrics.fragments > limits.max_fragments, "too many fragments"),
        (metrics.variables > limits.max_variables, "too many variables"),
        (metrics.max_depth > limits.max_depth, "query exceeds depth limit"),
        (metrics.fields > limits.max_fields, "query exceeds field limit"),
        (metrics.aliases > limits.max_aliases, "query exceeds alias limit"),
        (metrics.uses_introspection and not limits.allow_introspection, "introspection is disabled"),
    )
    for failed, message in checks:
        if failed:
            raise QueryLimitError(message)
    return document, metrics


def validate_query(query: str | bytes, limits: QueryLimits = QueryLimits()) -> QueryMetrics:
    """Compatibility helper for callers that only need structural metrics."""
    return parse_and_check_limits(query, limits)[1]
