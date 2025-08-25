# 🤝 Contributing to Secure Token

Welcome! We're excited that you want to contribute to the Secure Token project. This guide will help you get started quickly.

## 🚀 Quick Start

### 1. Clone & Setup
```bash
# Clone the repository
git clone https://github.com/amirhosein2004/secure-token.git
cd secure-token

# Install
pip install -e

# Install pre-commit hooks
pre-commit install
```

### 2. Development with Docker
```bash
# Build development environment
docker build -t secure-token:dev .

# Run development container
docker run -d -it -p 8000:8000 --name secure-token secure-token:dev
```

## 🧪 Testing

### Run Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/secure_token --cov-report=html

# Run specific test file
pytest tests/test_token_manager.py
```

### Performance Testing
```bash
# Run benchmark tests
python -m scripts.benchmark
```

## 📝 Making Changes

### 1. Create a Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes
- Write clear, concise code
- Add tests for new functionality
- Update documentation if needed
- Follow existing code style

### 3. Submit Pull Request
- Push your branch to GitHub
- Create a Pull Request with:
  - Clear title and description
  - Reference any related issues
  - Include test results if applicable

## 📁 Project Structure

```
secure-token/
├── src/secure_token/     # Main package code
├── tests/               # Test files
├── examples/            # Usage examples
├── scripts/             # Utility scripts (benchmark, deploy)
├── docs/               # Documentation
```

## 🐛 Reporting Issues

Found a bug? Please create an issue on [GitHub Issues](https://github.com/amirhosein2004/secure-token/issues) with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment details

## 💡 Development Tips

- Use the examples in `examples/` to understand
- Check `scripts/benchmark.py` for performance testing
- All code must pass CI checks before merging
- Docker is used for consistent development environment

## 📚 Resources

- [Development Documentation](https://github.com/amirhosein2004/secure-token)
- [Reference](https://github.com/amirhosein2004/secure-token)
- [GitHub Repository](https://github.com/amirhosein2004/secure-token)

---

Thank you for contributing! 🎉
