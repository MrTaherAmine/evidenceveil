# Policy Authoring

Policies are safe-loaded YAML documents with `policy_version`, identity, release model, key scope, optional TLP 2.0 metadata, ordered rules, utility requirements, and risk controls. Higher `priority` wins. Policies cannot explicitly keep authentication secrets or tokens. Use the JSON Schema in `schemas/policy.schema.json` for editor validation.
