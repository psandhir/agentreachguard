## Summary

Describe the change and the security problem it addresses.

## Evidence

- [ ] Tests added or updated.
- [ ] Secure counterexample included where applicable.
- [ ] Finding severity is justified.
- [ ] Scanner does not execute/import target code.
- [ ] Documentation updated if user-visible behaviour changed.

## Validation

```text
pytest -q
ruff check src tests
```

## Security impact

Describe any change to trust boundaries, parsing of untrusted repositories, credentials, network access, or generated findings.
