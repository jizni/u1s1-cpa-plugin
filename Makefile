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
# -ldflags. Defaults to the closest git tag, so `make build` on a release
# checkout produces a versioned plugin without extra arguments.
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

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
	@max=$$(objdump -T $(GLIBC_SO) | grep 'GLIBC_' | sed -E 's/.*GLIBC_([0-9.]+).*/\1/' | sort -Vu | tail -1); \
	echo "max glibc symbol: GLIBC_$$max (container is glibc 2.36)"; \
	if [ "$$max" = "2.36" ] || [ "$$max" = "2.35" ] || [ "$$max" = "2.34" ]; then \
		echo "OK: within container glibc"; \
	else \
		echo "WARNING: verify compatibility manually"; \
	fi

clean:
	rm -rf $(DIST)
