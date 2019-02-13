.PHONY: chain
chain:
	bash scripts/start_chain

.PHONY: chain_new
chain_new:
	bash scripts/start_chain_new

.PHONY: manual
manual:
	bash start_chain manual

.PHONY: style
style:
	autopep8 --in-place *.py tests/*.py

.PHONY: lint
lint:
	MYPYPATH="stubs" mypy --show-traceback --ignore-missing-imports EntryPoint.py ExitPoint.py Mix.py tests/*.py
	flake8 --ignore E501,SF01 *.py */*.py
	pylint3 --rcfile config/pylint3.cfg *.py */*.py

.PHONY: stop
stop:
	bash scripts/stop_chain

.PHONY: test
test: chain
	bash scripts/start_tests

.PHONY: test_new
test_new: chain_new
	bash scripts/start_tests

.SILENT: delay-test
.PHONY: delay-test
delay-test: chain test-delay stop

test-delay:
	PYTHONPATH="." tests/Delay_Test.py

.PHONY: coverage
coverage: export PYTHONPATH=.
coverage:
	py.test --cov=. tests/*_test.py

.PHONY: function-test
function-test: export PYTHONPATH=.
function-test:
	py.test tests/*_test.py

