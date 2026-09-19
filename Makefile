# Caesar cipher tool — common tasks.
# Run `make` or `make help` to see what is available.

PYTHON ?= python3

.DEFAULT_GOAL := help
.PHONY: help test verbose coverage demo clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

test: ## Run the full test suite
	@./run_tests.sh

verbose: ## Run the test suite with per-test output
	@./run_tests.sh -v

coverage: ## Run tests under coverage.py (pip install coverage)
	@$(PYTHON) -m coverage run -m unittest discover -s tests -t . \
		&& $(PYTHON) -m coverage report -m \
		|| echo "coverage not installed: pip install coverage"

# printf, not `echo -n`: the shell make uses on macOS prints a literal "-n".
demo: ## Encrypt, decrypt and crack a sample message
	@printf 'plaintext : Attack at dawn!\n'
	@printf 'encrypted : '; $(PYTHON) main.py encrypt "Attack at dawn!" --shift 3
	@printf 'decrypted : '; $(PYTHON) main.py decrypt "Dwwdfn dw gdzq!" --shift 3
	@printf 'cracked   : (top 3 by English-likeness)\n'
	@$(PYTHON) main.py crack "Dwwdfn dw gdzq!" --rank --top 3 | sed 's/^/            /'

clean: ## Remove caches and bytecode
	@find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .coverage htmlcov .pytest_cache
	@echo "cleaned"
