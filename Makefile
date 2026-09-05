# u1s1-cpa-plugin build tooling.
#
# Build artifacts go to dist/ so the repo root stays source-only. The plugin
# must be built with CGO (c-shared) and on a host whose glibc is not newer than
# the target CPA container's (see README §构建).

GO       ?= go
DIST     := dist
PLUGIN   := $(DIST)/u1s1.so
LDFLAGS  := -s -w

# Release version, injected into the plugin's registration metadata via
# -ldflags. Defaults to the closest git tag with the leading v stripped (so
# v0.2.0 -> 0.2.0, matching .github/workflows/release.yml), so `make build` on
# a release checkout produces a versioned plugin without extra arguments.
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)

# glibc-check.sh holds the single target-glibc constant (2.36 = Debian 12,
# matching the CPA container) and does a version-ordered comparison; see
# scripts/glibc-check.sh for why the check must be <=, not an equality list.
GLIBC_CHECK := scripts/glibc-check.sh

.PHONY: all build test vet race ci clean glibc-check

all: build

build:
	mkdir -p $(DIST)
	CGO_ENABLED=1 $(GO) build -buildmode=c-shared -trimpath \
		-ldflags "$(LDFLAGS) -X main.pluginVersion=$(VERSION)" -o $(PLUGIN) .
	@echo "built $(PLUGIN) (version $(VERSION))"
	@$(MAKE) glibc-check GLIBC_SO=$(PLUGIN)

test:
	$(GO) test ./...

race:
	CGO_ENABLED=1 $(GO) test -race ./...

vet:
	$(GO) vet ./...

# ci runs the same pipeline as .github/workflows/ci.yml.
ci: build test race vet

# glibc-check verifies the shared object only requires glibc symbols the CPA
# container provides (Debian 12 / glibc 2.36). Run with GLIBC_SO=<path>.
GLIBC_SO ?= $(PLUGIN)
glibc-check:
	@GLIBC_SO=$(GLIBC_SO) $(GLIBC_CHECK)

clean:
	rm -rf $(DIST)
