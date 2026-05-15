# Contributing to Agentic-IAM

Thank you for your interest in contributing to Agentic-IAM. We welcome improvements, bug fixes, tests, and documentation.

Getting started

1. Fork the repository and create a branch: `git checkout -b feat/your-feature`.
2. Install dependencies and run tests locally.
3. Add or update tests for your changes.
4. Commit with clear messages (Conventional Commits recommended).
5. Open a Pull Request describing the change and link any relevant issue.

Code style and linters

- Run `flake8 .` to check style and linting issues.
- Run `bandit -r .` to check for common security issues.

Testing

- Unit tests: `pytest tests/unit`
- Integration tests: `pytest tests/integration`
- E2E tests: `pytest tests/e2e` (requires running dashboard and E2E env vars)

CI

All PRs should pass CI (`.github/workflows/ci.yml`) before merge.

License

By contributing you agree your contributions will be licensed under the project's MIT license.
