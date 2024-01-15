export CGO_ENABLED := 1
include Makefile.Inc

smtool: get-postrs-lib
	go1.21.5 build -o $(BIN_DIR)$@$(EXE) .
.PHONY: smtool