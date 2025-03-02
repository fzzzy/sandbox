.PHONY: all build

all:
	echo "hello world"

build: venv node_modules

venv:
	echo "hello python"

node_modules:
	echo "hello typescript"
