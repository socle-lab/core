## test: runs all tests
test:
	@go test -v ./...

## cover: opens coverage in browser
cover:
	@go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

## coverage: displays test coverage
coverage:
	@go test -cover ./...

## build_cli: builds the command line tool socle and copies it to myapp
build_cli:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../socle-seed/cli ./cmd/cli

## build: builds the command line tool dist directory
build:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./socle ./cmd/cli

install_cli:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ~/go/bin/socle -ldflags '-s -w' ./cmd/cli