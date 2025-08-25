# 🧪 Testing Guide

Complete guide for testing the Secure Token package.

## 🚀 Running Tests

### Basic Test Commands
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_token_manager.py

# Run tests matching pattern
pytest -k "test_generate"
```

### Coverage Testing
```bash
# Run tests with coverage
pytest --cov=src/secure_token

# Generate HTML coverage report
pytest --cov=src/secure_token --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS/Linux
start htmlcov/index.html # Windows
```

## 📊 Performance Testing

### Benchmark Tests
```bash
# Full benchmark suite
python scripts/benchmark.py

# Specific benchmarks
python -m scripts.benchmark generation 1000    # Token generation
python -m scripts.benchmark validation         # Token validation
python -m scripts.benchmark concurrent 500 8   # Concurrent generation
python -m scripts.benchmark memory 1000        # Memory usage
```

### Expected Performance
- **Generation**: ~19,000 tokens/second
- **Validation**: ~21,000 validations/second
- **Concurrent**: ~2,700 tokens/second (10 workers)
- **Memory**: <4KB per token

## 🔧 Test Configuration

### pytest Configuration
Tests are configured in `pytest.ini`:
- Test discovery in `tests/` directory
- Coverage source: `src/secure_token`
- Excludes: test files, main modules

### Coverage Settings
Coverage configured in `pyproject.toml`:
- Source: `src/secure_token`
- Omits: tests, `__main__.py`
- Excludes: pragma comments, abstract methods

## 📝 Writing Tests

### Test Structure
```python
import pytest
from secure_token import SecureTokenManager

def test_token_generation():
    manager = SecureTokenManager()
    token = manager.generate_token("test_user")
    assert isinstance(token, str)
    assert len(token) > 0
```

### Test Categories
- **Unit tests**: Individual function testing
- **Integration tests**: Component interaction
- **Performance tests**: Speed and memory benchmarks
- **Security tests**: Encryption and validation

## 🐳 Docker Testing

```bash
# Build test container
docker build -t secure-token:test .

# Run tests in container
docker run --rm secure-token:test pytest

# Run with coverage
docker run --rm secure-token:test pytest --cov=src/secure_token
```

## 🔍 Quality Checks

### Code Quality Tools
```bash
# Format check
black --check src/ tests/

# Import sorting
isort --check-only src/ tests/

# Linting
flake8 src/ tests/

# Type checking
mypy src/

# Security analysis
bandit -r src/

# pre commit before commit(manual)
pre-commit run --all-files
```

All quality checks run automatically with pre-commit hooks!
