# Contributing to AgentContainment

Thanks for helping. This guide keeps changes reviewable and the security boundary intact.

## Workflow

1. Open an issue first for anything larger than a small fix, so the approach can be agreed.
2. Branch from `main` and keep each pull request to one theme.
3. Run the test suite locally: `python -m pytest -q`.
4. Add or update tests for any behavior change, especially anything security-relevant.
5. Open a pull request using the template. CI must be green before review; the default branch is protected and requires passing checks.

## Developer Certificate of Origin (DCO)

Every commit must be signed off (`git commit -s`), certifying the [Developer Certificate of Origin](https://developercertificate.org/):

```
Signed-off-by: Your Name <you@example.com>
```

## Licensing

Contributions are made under Apache License 2.0 (see `LICENSE`).

## Security issues

Do not file public issues for vulnerabilities. Follow `SECURITY.md`.
