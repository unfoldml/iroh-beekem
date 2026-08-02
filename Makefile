# Developer entry points. CI runs the same commands; see .github/workflows/ci.yml.
#
# CLAUDE.md has pointed contributors at `make coverage` and COVERAGE.md as the
# standing to-do surface since before either existed. This is that target.

# rustfmt.toml uses nightly-only options, so the toolchain is pinned: an
# unpinned nightly changes the expected formatting and the check fails for
# reasons unrelated to the diff.
NIGHTLY := nightly-2025-11-21

# The floor `make coverage-check` enforces. Advisory today — deliberately not
# wired into `make check` — but a drop on files you touched is a defect to fix
# before declaring done, not a number to lower.
COVERAGE_FLOOR ?= 70

.PHONY: help check test lint fmt fmt-check purity coverage coverage-check publish-dry example clean

help:
	@echo "check         test + lint + fmt-check + purity (what CI gates on)"
	@echo "test          the three suites; the sim one takes ~5 min"
	@echo "lint          clippy over the workspace, warnings denied"
	@echo "fmt / fmt-check   rustfmt with the pinned nightly"
	@echo "purity        prove iroh-beekem-core has no tokio/iroh/quinn"
	@echo "coverage      regenerate COVERAGE.md across every test manifest"
	@echo "coverage-check    fail if total line coverage is below \$$COVERAGE_FLOOR"
	@echo "publish-dry   cargo publish --dry-run over the workspace"
	@echo "example       run the two-peer example end to end"

check: test lint fmt-check purity

# One suite at a time, deliberately. `cargo test --workspace` builds one job
# graph and runs the simulator and the real-QUIC suite *concurrently* — the exact
# combination CLAUDE.md says never to run, because the QUIC tests wait on
# wall-clock outcomes and the simulator saturates every core it is given. The
# failures land in the QUIC suite, name assorted `eventually` waits, and look
# nothing like their cause.
test:
	cargo test -p iroh-beekem-core
	cargo test -p iroh-beekem-sim
	cargo test -p iroh-beekem

lint:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo +$(NIGHTLY) fmt --all

fmt-check:
	cargo +$(NIGHTLY) fmt --all --check

# The one structural rule in CLAUDE.md, enforced mechanically rather than by
# review: the core performs no I/O, so it must not depend on a runtime, a
# transport, or a clock. Matching anything here is a failure.
purity:
	@if cargo tree -p iroh-beekem-core -e normal --prefix none \
	    | sort -u | grep -Ev '^iroh-beekem' | grep -E '^(tokio|iroh|quinn)\b'; then \
	  echo "FAIL: iroh-beekem-core gained an I/O dependency; see CLAUDE.md"; \
	  exit 1; \
	else \
	  echo "ok: iroh-beekem-core is I/O-free"; \
	fi

# Merged across every test manifest, so a line covered only by the simulator
# still counts. Without `--workspace` the report would credit each crate only
# for its own tests and understate the core badly — most of the core's coverage
# comes from propsim driving it.
COVERAGE_ARGS := --workspace --all-targets --ignore-filename-regex '(tests?/|examples/)'

coverage:
	cargo llvm-cov $(COVERAGE_ARGS) --summary-only --json --output-path target/coverage.json
	@python3 scripts/coverage_report.py target/coverage.json > COVERAGE.md
	@echo "wrote COVERAGE.md"

coverage-check:
	cargo llvm-cov $(COVERAGE_ARGS) --summary-only --fail-under-lines $(COVERAGE_FLOOR)

publish-dry:
	# Workspace mode, not two per-crate runs: `iroh-beekem` depends on
	# `iroh-beekem-core` by version as well as by path, so a per-crate dry run
	# cannot resolve it against the registry until core is actually released.
	cargo publish --dry-run --workspace

example:
	cargo run -p iroh-beekem --example two_node

clean:
	cargo clean
	rm -f target/coverage.json
