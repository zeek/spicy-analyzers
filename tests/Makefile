
all: test
test: test-build

test-build:
	@btest -j -d

# Might need to have SPICY_INSTALLATION_DIRECTORY set.
test-install:
	@btest -j -d -a installation

clean:
	@rm -f $(DIAG) .btest.failed.dat
	@rm -rf .tmp

.PHONY: all test-build clean
