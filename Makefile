SHELL := /bin/bash

.PHONY: validate bootstrap
validate:
	python3 scripts/validate_repo.py

bootstrap:
	./scripts/bootstrap-development.sh
