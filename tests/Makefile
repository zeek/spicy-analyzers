
all: test-build

test-build:
	@btest -j -d

clean:
	@rm -f $(DIAG) .btest.failed.dat
	@rm -rf .tmp

.PHONY: all test-build clean
