.PHONY: help install test lint format clean docker-build docker-run security-scan

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@egrep '^(.+)\s*:.*?## (.+)' $(MAKEFILE_LIST) | column -t -c 2 -s ':#'

install: ## Install dependencies
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

test: ## Run tests
	python -m pytest test_app.py -v --cov=app --cov-report=xml

lint: ## Run linting
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=88 --statistics

format: ## Format code
	black .
	isort .

format-check: ## Check code formatting
	black --check .
	isort --check-only .

clean: ## Clean up generated files
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov
	rm -rf dist
	rm -rf build
	rm -rf *.egg-info

docker-build: ## Build Docker image
	docker build -t flask-app:latest .

docker-run: ## Run Docker container
	docker run -p 5000:5000 flask-app:latest

docker-compose-up: ## Start services with docker-compose
	docker-compose up -d

docker-compose-down: ## Stop services with docker-compose
	docker-compose down

security-scan: ## Run security scans locally
	bandit -r . -f json -o bandit-report.json || true
	safety check --json --output safety-report.json || true
	@echo "Security scan reports generated: bandit-report.json, safety-report.json"

run: ## Run the Flask application
	python app.py

dev-setup: ## Set up development environment
	python -m venv venv
	@echo "Virtual environment created. Activate with:"
	@echo "source venv/bin/activate  # On Linux/Mac"
	@echo "venv\\Scripts\\activate     # On Windows"
