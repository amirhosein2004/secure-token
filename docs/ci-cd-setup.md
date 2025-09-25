# CI/CD Setup Guide

This document provides guidance for setting up **Continuous Integration (CI) and Continuous Deployment (CD)** for the Secure Token project.

## Overview

The CI/CD pipeline is configured using **GitHub Actions** and includes the following features:

* Automated testing across multiple Python versions
* Code coverage reporting
* Automatic publishing to PyPI
* Git tagging for releases

---

## Workflow Structure

The workflow file `.github/workflows/ci-cd.yml` contains two main jobs:

### 1. Test Job

```yaml
test:
  runs-on: ubuntu-latest
  strategy:
    matrix:
      python-version: [3.8, 3.9, "3.10", "3.11", "3.12"]
```

**Steps:**

* **Checkout Code:** Pulls the code from the repository
* **Set up Python:** Installs different Python versions (3.8 to 3.12)
* **Install Dependencies:** Installs required packages for testing
* **Run Tests:** Executes pytest with code coverage
* **Upload Coverage:** Sends the coverage report to Codecov

---

### 2. Publish Job

```yaml
publish:
  needs: test
  runs-on: ubuntu-latest
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
```

**Execution Conditions:**

* Only runs after the test job succeeds
* Only runs on push to the `main` branch

**Steps:**

1. **Checkout with full history:** Fetches the code along with all Git tags
2. **Set up Python 3.11:** Required for building the package
3. **Install Build Tools:** Installs `build` and `twine`
4. **Read Version:** Extracts the version from `pyproject.toml`
5. **Check Tag Existence:** Verifies if the tag already exists
6. **Build Package:** Builds the Python package
7. **Publish to PyPI:** Uploads the package to PyPI
8. **Create Tag:** Creates and pushes a Git tag

---

## Required Setup

### 1. PyPI API Token

For automatic publishing to PyPI:

1. Go to [PyPI](https://pypi.org/) and log in
2. Navigate to **Account Settings → API tokens**
3. Click **Add API token**
4. Name it: `GitHub Actions`
5. Scope: Specify project (recommended)
6. Copy the token

### 2. GitHub Secret

In your GitHub repository:

1. Go to **Settings → Secrets and variables → Actions**
2. Click **New repository secret**
3. Name: `PYPI_API_TOKEN`
4. Value: Paste your PyPI token

---

## Workflow Triggers

| Event                  | Description                   | Jobs Executed  |
| ---------------------- | ----------------------------- | -------------- |
| Push to `main`         | New commit on the main branch | Test + Publish |
| Pull Request           | Merge request                 | Test only      |
| Push to other branches | Commits on other branches     | Test only      |

---

## Version Management

* Version is read from `pyproject.toml`
* Tag format: `v{version}` (e.g., `v1.0.1`)
* If the tag exists, publishing is skipped
* Tags are automatically created and pushed

---

## Local Testing

Before pushing:

```bash
# Install test dependencies
pip install -e .[test]

# Run tests
pytest

# Check coverage
pytest --cov=src/secure_token --cov-report=html

# Build package (optional)
python -m build
```

---

## Troubleshooting

### Common Issues

**1. PyPI Publish Error**

```
Error: Invalid or non-existent authentication information
```

* Verify `PYPI_API_TOKEN` is set correctly
* Ensure the token is not expired

**2. Duplicate Tag**

```
Tag v1.0.1 already exists
```

* Increment the version in `pyproject.toml`
* Or delete the existing tag

**3. Failing Tests**

```
Tests failed, skipping publish
```

* Run tests locally
* Fix the failing issues

### Useful Logs

For debugging:

* **GitHub Actions tab**
* Step-by-step logs
* pytest and twine output

---

## Manual Release

If needed:

```bash
# Build package
python -m build

# Upload to PyPI
twine upload dist/*

# Tag the release
git tag -a v1.0.2 -m "Release v1.0.2"
git push origin v1.0.2
```

---

## Best Practices

1. **Versioning:** Always update the version in `pyproject.toml`
2. **Testing:** Run tests locally before pushing
3. **CHANGELOG:** Keep a `CHANGELOG.md` updated with changes
4. **Security:** Never commit tokens or secrets to the repository

---

## Full Workflow Example

Release process:

1. Code changes
2. Increment version in `pyproject.toml`
3. Update `CHANGELOG.md`
4. Commit and push to `main`
5. GitHub Actions:

   * Tests run
   * Package is built
   * Package is published to PyPI
   * Git tag is created and pushed
6. Release complete! 🎉
