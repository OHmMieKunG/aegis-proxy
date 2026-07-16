# ADR-0005: Strict TOML configuration

Status: Accepted
Date: 2026-07-16

## Context

Operators need reviewable, offline, versioned desired state.

## Constraints

Unknown fields, shell expansion, arbitrary scripts, and plaintext inline secrets are forbidden.

## Options considered

Strict TOML; YAML; JSON-only; database-authored config.

## Decision

Use recursive `deny_unknown_fields` TOML with JSON API representations later.

## Rationale

TOML is readable and avoids YAML implicit typing/alias behavior; files work without a database.

## Consequences

Schema migrations and file atomicity are explicit responsibilities.

## Security implications

Bounded parsing and cross-field validation occur before any listener starts.

## Reliability implications

Last-known-good revisions remain available after invalid edits.

## Operational implications

CLI validate/preview/diff works offline.

## Migration implications

Schema versions are transformed into new files; startup never rewrites the source.

## Alternatives rejected

Unbounded raw snippets and runtime templating.

## Revisit conditions

Proven need for a different source that preserves strict validation semantics.
