.PHONY: chain
chain:
	bash start_chain

.PHONY: test
test: chain
	bash start_tests

.PHONY: manual
manual:
	bash start_chain manual

.PHONY: lint
lint:
	mypy --show-traceback stubs/ Test_Client.py EntryPoint.py ExitPoint.py Mix.py Recv.py
	flake8 --max-line-length=80 *.py */*.py
	pylint3 --rcfile config/pylint3.cfg *.py */*.py
