
.PHONY: build clean test

build:
	dune build --dev

test:
	dune runtest --dev

install:
	dune install

uninstall:
	dune uninstall

clean:
	dune clean
