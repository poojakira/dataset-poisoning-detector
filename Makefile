.PHONY: install test test-security test-integration test-all lint format audit build docker-build deploy-dev deploy-prod clean

install:
	pip install -e ".[dev,realtime,security]"

test:
	pytest tests/ -v

test-security:
	pytest tests/test_auth.py tests/test_crypto.py tests/test_audit.py -v

test-integration:
	pytest tests/integration/ -v

test-all:
	pytest tests/ -v --cov=poison_detector --cov-report=term-missing

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

audit:
	pip-audit

build:
	python -m build

docker-build:
	docker build -t poison-detector:latest .

deploy-dev:
	# Deploy to development environment using kustomize dev overlay
	kubectl apply -k k8s/

deploy-prod:
	# Deploy to production environment using kustomize prod overlay
	kubectl apply -k k8s/

clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache
