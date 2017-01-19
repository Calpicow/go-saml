# Makefile variables
PROJECT_NAME=go-saml
RUN=docker-compose run --rm ${PROJECT_NAME}

# List of packages 1 package per line relative to current location
PKG_ML = $(shell go list ./... | sed "s%_$$(pwd)%\.%g" | grep -v vendor)
# List of packages space delimited
PKG = $(shell echo ${PKG_ML} | tr "\n" " ")
# All .go files, excluding the vendors
GOFILES = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

# Color variables
NO_COLOR=\033[0m
OK_COLOR=\033[32;01m
ERROR_COLOR=\033[31;01m
WARN_COLOR=\033[33;01m

default: build

build: vet
	@echo "$(OK_COLOR)==> Go Building(NO_COLOR)"
	go build ./...

init:
	go get github.com/nu7hatch/gouuid
	go get github.com/kardianos/osext
	go get github.com/stretchr/testify/assert
	go get github.com/ma314smith/signedxml

vet: init
	@echo "$(OK_COLOR)==> Go Vetting$(NO_COLOR)"
	go vet ./...

test: vet
	@echo "$(OK_COLOR)==> Testing$(NO_COLOR)"
	go test ./...

.PHONY: default build init test vet

# Docker initiated commands

# Build via docker
buildx: depx depinfox
	mkdir -p dist
	${RUN} go build -o dist/${PROJECT_NAME}

# Test via docker
testx: depinfox fmtx lintx
	${RUN} go test -v ${PKG}

# Test coverage via docker
coverx:
	mkdir -p reports
	${RUN} echo "mode: count" > reports/coverage-all.out
	$(foreach pkg,$(PKG_ML), \
		${RUN} bash -c "go test -coverprofile=reports/coverage.out -covermode=count $(pkg)"; \
		${RUN} tail -n +2 reports/coverage.out >> reports/coverage-all.out; \
	)
	${RUN} go tool cover -html=reports/coverage-all.out -o reports/coverage.html

# Lint via docker
lintx:
	${RUN} bash -c "for pkg in ${PKG}; do echo \$$pkg && go vet \$$pkg && golint \$$pkg; done"

# Load dependencies via docker
depx:
	${RUN} bash -c "govendor sync"

# Load dependency information via docker
depinfox:
	${RUN} bash -c "govendor list && govendor status"

# Format code via docker
fmtx:
	${RUN} bash -c "goimports -w ${GOFILES} && gofmt -l -s -w ${GOFILES}"

# Remove all app artifacts
cleanx:
	docker-compose down
	rm -f reports dist
