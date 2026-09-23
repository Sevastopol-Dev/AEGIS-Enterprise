# ==============================================================================
# Aegis v4 - Local Execution & Automation Makefile
# ==============================================================================

.PHONY: all setup build up down init plan apply test clean

# Default target
all: setup build up init apply test

# 1. Environment Setup Check
setup:
	@echo "Checking prerequisites..."
	@command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting."; exit 1; }
	@command -v tflocal >/dev/null 2>&1 || { echo "tflocal is required. Install via 'pip install terraform-local'. Aborting."; exit 1; }
	@command -v awslocal >/dev/null 2>&1 || { echo "awslocal is required. Install via 'pip install awscli-local'. Aborting."; exit 1; }
	@echo "All prerequisite CLI tools found."

# 2. Package Python Immune Worker into Deployment Zip
build:
	@echo "Packaging Immune Worker Lambda payload..."
	@mkdir -p terraform
	@cd src/immune_worker && zip -FS -r ../../terraform/immune_worker.zip immune_worker.py
	@echo "Created terraform/immune_worker.zip successfully."

# 3. LocalStack Container Management
up:
	@echo "Starting LocalStack container..."
	docker-compose up -d

down:
	@echo "Stopping LocalStack container..."
	docker-compose down
	
	
status: ## Check status of LocalStack services
	@curl -s http://localhost:4566/_localstack/health | jq | grep -E "(available|running)"
	
	

# 4. Terraform Workflows (via tflocal)
init:
	@echo "Initializing Terraform against LocalStack..."
	@cd terraform && tflocal init

plan: build
	@echo "Generating Terraform plan..."
	@cd terraform && tflocal plan

apply: build
	@echo "Applying Aegis v4 architecture to LocalStack..."
	@cd terraform && tflocal apply -auto-approve

destroy:
	@echo "Tearing down Aegis v4 local resources..."
	@cd terraform && tflocal destroy -auto-approve

# 5. Automated Verification Test Trigger
test:
	@echo "Executing Aegis v4 Honeytoken Breach & Auto-Remediation Test..."
	@chmod +x tests/trigger_honeytoken.sh
	@./tests/trigger_honeytoken.sh

# 6. Clean Artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f terraform/immune_worker.zip
	@rm -rf terraform/.terraform terraform/.terraform.lock.hcl terraform/terraform.tfstate*
	@echo "Cleanup complete."
	
# 7. Trivy Static Analysis	
	
scan: ## Run Trivy vulnerability scan on IaC
	docker run --rm -v $(PWD):/src aquasec/trivy:latest config /src --severity HIGH,CRITICAL
	
	
# 8. Local GitHub Actions Workflows

act-test: ## Run GitHub Actions workflows locally
	act -W .github/workflows/deploy.yml
