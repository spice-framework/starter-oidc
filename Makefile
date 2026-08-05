.PHONY: acceptance check fmt verify

acceptance:
	go test -race -shuffle=on -count=1 .

check:
	go run ./internal/qualitygate -mode=check

fmt:
	go run ./internal/qualitygate -mode=fmt

verify:
	go run ./internal/qualitygate -mode=verify
