
.PHONY: build clean test

build:
	jbuilder build lib_test/test.exe
	jbuilder build @install

test:
	jbuilder runtest

install:
	jbuilder install

uninstall:
	jbuilder uninstall

clean:
	rm -rf _build
