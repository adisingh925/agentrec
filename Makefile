IMAGE ?= agentrec
RUN   := docker run --rm --privileged --pid=host

.PHONY: build demo trace shell info clean

build:
	docker build --target runtime -t $(IMAGE) .

# Record the stand-in agent and print the attributed timeline (uses the demo-only image).
demo:
	docker build --target demo -t $(IMAGE)-demo .
	$(RUN) $(IMAGE)-demo trace --session demo --out /tmp/rec.json -- /demo/fake-agent.sh

# Record an arbitrary command: make trace CMD="sh -c 'curl -s example.com'"
trace: build
	$(RUN) $(IMAGE) trace --session adhoc -- sh -c "$(CMD)"

shell:
	docker build --target demo -t $(IMAGE)-demo .
	$(RUN) -it --entrypoint /bin/bash $(IMAGE)-demo

info: build
	$(RUN) $(IMAGE) info

clean:
	rm -f bpf/vmlinux.h internal/probe/agentrec_bpfel.* go.sum
