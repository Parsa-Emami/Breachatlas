.PHONY: validate next status hashes bootstrap dev build test package
validate:
	python3 scripts/plan.py validate
next:
	python3 scripts/plan.py next
status:
	python3 scripts/plan.py status
hashes:
	python3 scripts/hashes.py --write
bootstrap:
	npm ci --ignore-scripts
	npm run build
dev:
	npm run dev
build:
	npm run build
test:
	npm test
package:
	npm run package:web
