.PHONY: chain
chain:
	bash start_chain

.PHONY: test
test: chain
	bash start_tests

.PHONY: manual
manual:
	bash start_chain manual
