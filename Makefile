.PHONY: chain
chain:
	bash scripts/start_chain

.PHONY: manual
manual:
	bash start_chain manual

.PHONY: lint
lint:
	mypy --show-traceback stubs/ Test_Client.py EntryPoint.py ExitPoint.py Mix.py Recv.py
	flake8 --max-line-length=80 *.py */*.py
	pylint3 --rcfile config/pylint3.cfg *.py */*.py

.PHONY: stop
stop:
	bash scripts/stop_chain

.PHONY: test
test: chain
	bash scripts/start_tests

.PHONY: delay-test
delay-test: chain test-delay stop

test-delay:
	bash tests/Delay-Jitter-Test.sh