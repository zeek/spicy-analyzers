# Helper for building Docker image locally for testing.

all:

build:
		DOCKER_BUILDKIT=1 docker build --build-arg "UID=$$(id -u)" --build-arg "GID=$$(id -g)" -t spicy-analyzers-ci:latest .

run:
	docker run -v $$(cd .. && pwd):/opt/spicy-analyzers -w /opt/spicy-analyzers --cap-add SYS_PTRACE --security-opt seccomp=unconfined -i -t spicy-analyzers-ci:latest /bin/bash

