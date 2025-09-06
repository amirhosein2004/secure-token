#!/bin/bash

# scriptfir deploy SecureToken
# usage: ./scripts/deploy.sh [version]

set -e

VERSION=${1:-"latest"}
REGISTRY="ghcr.io/amirhosein2004"
IMAGE_NAME="secure-token"

echo "🚀 Start deploy process for version $VERSION"

# check if docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed"
    exit 1
fi

# run tests
echo "🧪 Run tests..."
python -m pytest tests/ --cov=src/secure_token --cov-fail-under=90

# check code quality
echo "🔍 Check code quality..."
black --check src/ tests/
isort --check-only src/ tests/
flake8 src/ tests/
mypy src/
bandit -r src/

# build package
echo "📦 Build package..."
python -m build

# build Docker image
echo "🐳 Build Docker image..."
docker build -t $REGISTRY/$IMAGE_NAME:$VERSION .
docker build -t $REGISTRY/$IMAGE_NAME:latest .

# run container tests
echo "🧪 Run container tests..."
docker run --rm $REGISTRY/$IMAGE_NAME:$VERSION python -c "from secure_token import SecureTokenManager; print('✅ Import successfully')"

# Push images
if [ "$2" = "--push" ]; then
    echo "📤 Push images..."
    docker push $REGISTRY/$IMAGE_NAME:$VERSION
    docker push $REGISTRY/$IMAGE_NAME:latest
    echo "✅ Images push successfully"
fi

echo "🎉 Deploy version $VERSION successfully"
