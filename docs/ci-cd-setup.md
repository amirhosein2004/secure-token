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
  permissions:
    contents: write      # Required for creating releases and tags
    id-token: write      # Required for authentication
```

**Execution Conditions:**

* Only runs after the test job succeeds
* Only runs on push to the `main` branch
* Has write permissions for repository contents

**Steps:**

1. **Checkout with full history:** Fetches the code along with all Git tags
2. **Set up Python 3.11:** Required for building the package
3. **Install Build Tools:** Installs `build` and `twine`
4. **Read Version:** Extracts the version from `pyproject.toml`
5. **Check Tag Existence:** Verifies if the tag already exists in Git
6. **Check PyPI Existence:** Verifies if the version already exists on PyPI
7. **Build Package:** Builds the Python package (if version is new)
8. **Publish to PyPI:** Uploads the package to PyPI (if version is new)
9. **Create GitHub Release:** Creates a GitHub Release with tag and changelog (if version is new)

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

**Note:** `GITHUB_TOKEN` is automatically provided by GitHub Actions - no manual setup required! ✅

---

## GitHub Release Features

The workflow automatically creates a **GitHub Release** for each new version with:

* **Tag:** `v{version}` (e.g., `v1.0.2`)
* **Release Notes:** Auto-generated with CHANGELOG link
* **Installation Command:** Copy-paste ready pip install command
* **PyPI Link:** Direct link to the package on PyPI

Example Release Body:

```markdown
## Changes in version 1.0.2

See CHANGELOG.md for details.

### Installation
pip install secure-token==1.0.2

### PyPI Package
https://pypi.org/project/secure-token/1.0.2/
```

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
* Tag format: `v{version}` (e.g., `v1.0.2`)
* Checks both Git tags and PyPI for existing versions
* If version exists anywhere, publishing is skipped (idempotent)
* GitHub Release is automatically created with tag
* Release includes changelog link and installation instructions

**Smart Duplicate Prevention:**

The workflow checks two places before publishing:

1. **Git Tags:** Prevents duplicate tag creation
2. **PyPI:** Prevents duplicate package upload

This ensures the workflow is **safe to re-run** without errors.

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

**Solution:**
* Verify `PYPI_API_TOKEN` is set correctly in GitHub Secrets
* Ensure the token is not expired
* Check the token has upload permissions

**2. Permission Denied (403)**

```
remote: Permission to repository denied to github-actions[bot]
fatal: unable to access: The requested URL returned error: 403
```

**Solution:**
* Ensure `permissions` are set in the workflow:
  ```yaml
  permissions:
    contents: write
    id-token: write
  ```
* This is already configured in the latest workflow ✅

**3. Duplicate Version**

```
Package version 1.0.2 already exists on PyPI
```

**Solution:**
* This is normal - workflow will skip publishing automatically ✅
* Increment the version in `pyproject.toml` for a new release

**4. Failing Tests**

```
Tests failed, skipping publish
```

**Solution:**
* Run tests locally: `pytest`
* Fix the failing issues
* Push again after fixes

### Useful Logs

For debugging:

* **GitHub Actions tab:** View all workflow runs
* **Step-by-step logs:** Detailed output for each step
* **pytest output:** Test results and coverage
* **twine output:** PyPI upload details
* **Release creation:** GitHub API responses

---

## Manual Release

If automatic workflow fails or you need manual control:

### Option 1: PyPI Only

```bash
# Build package
python -m build

# Upload to PyPI
twine upload dist/*
```

### Option 2: Complete Release

```bash
# 1. Build and upload to PyPI
python -m build
twine upload dist/*

# 2. Create GitHub Release (via web interface)
# Go to: https://github.com/amirhosein2004/secure-token/releases/new
# - Tag: v1.0.2
# - Title: Release v1.0.2
# - Description: See CHANGELOG.md
```

**Note:** Automatic workflow is recommended - it handles everything correctly! ✅

---

## Best Practices

1. **Versioning:** Always update the version in `pyproject.toml`
2. **Testing:** Run tests locally before pushing
3. **CHANGELOG:** Keep a `CHANGELOG.md` updated with changes
4. **Security:** Never commit tokens or secrets to the repository

---

## Full Workflow Example

Complete release process:

### Step 1: Make Changes

```bash
# Make your code changes
# Update tests
```

### Step 2: Update Version

```toml
# pyproject.toml
version = "1.0.2"  # Increment version
```

### Step 3: Update CHANGELOG

```markdown
# CHANGELOG.md
## [1.0.2] - 2025-11-05

### Changed
- Your changes here
```

### Step 4: Commit and Push

```bash
git add .
git commit -m "Release v1.0.2"
git push origin main
```

### Step 5: Automatic CI/CD

GitHub Actions automatically:

1. ✅ **Runs tests** on Python 3.10, 3.11, 3.12
2. ✅ **Checks for duplicate** version on Git and PyPI
3. ✅ **Builds package** if version is new
4. ✅ **Publishes to PyPI** if version is new
5. ✅ **Creates GitHub Release** with:
   - Tag: `v1.0.2`
   - Release notes with CHANGELOG link
   - Installation instructions
   - PyPI package link

### Step 6: Verify

* Check PyPI: https://pypi.org/project/secure-token/1.0.2/
* Check GitHub Releases: https://github.com/amirhosein2004/secure-token/releases

### Result: Release complete! 🎉

Users can now install:
```bash
pip install secure-token==1.0.2
```

---

## Summary

| Feature | Status |
|---------|--------|
| Automatic Testing | ✅ Multi-version Python support |
| Smart Duplicate Detection | ✅ Git tags + PyPI checking |
| PyPI Publishing | ✅ Automatic with token |
| GitHub Release | ✅ Auto-created with notes |
| Permissions | ✅ Built-in GITHUB_TOKEN |
| Idempotent | ✅ Safe to re-run |

**Only one secret needed:** `PYPI_API_TOKEN` 🎉
