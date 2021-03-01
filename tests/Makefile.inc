# Helper to be included from individual analyzers.

all: test

test:
	@tests=$$(pwd | sed "s@$$(git rev-parse --show-toplevel)/@@g" | sed 's@/@.@g') \
	cd $$(git rev-parse --show-toplevel)/tests && btest -j -d $${tests} 

test-update:
	@tests=$$(pwd | sed "s@$$(git rev-parse --show-toplevel)/@@g" | sed 's@/@.@g') \
	cd $$(git rev-parse --show-toplevel)/tests && btest -u $${tests} 
