
DIAG=diag.log

.PHONY: all
all: test

.PHONY: all-ci
all-ci: test

.PHONY: test
test:
	@btest -j -f $(DIAG)

.PHONY: clean
clean:
	@rm -f $(DIAG) .btest.failed.dat
	@rm -rf .tmp

