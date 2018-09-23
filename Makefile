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
	mypy Test_Client.py EntryPoint.py ExitPoint.py Mix.py Recv.py
	flake8 *.py */*.py
	pylint3 --rcfile pylint3.cfg *.py */*.py
