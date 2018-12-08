.PHONY: chain
chain:
	bash scripts/start_chain

.PHONY: manual
manual:
	bash start_chain manual

.PHONY: style
style:
	autopep8 --in-place *.py tests/*.py

.PHONY: lint
lint:
	MYPYPATH="stubs" mypy --show-traceback --ignore-missing-imports EntryPoint.py ExitPoint.py Mix.py tests/*.py
	flake8 --max-line-length=80 *.py */*.py
	pylint3 --rcfile config/pylint3.cfg *.py */*.py

.PHONY: stop
stop:
	bash scripts/stop_chain

.PHONY: test
test: chain
	bash scripts/start_tests

.SILENT: delay-test
.PHONY: delay-test
delay-test: chain test-delay stop

test-delay:
	bash tests/Delay-Jitter-Test.sh


.PHONY: function-test
function-test:
	PYTHONPATH="." tests/MixMessage_test.py
	PYTHONPATH="." ./util_tests.py

