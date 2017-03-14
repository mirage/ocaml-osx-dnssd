
.PHONY: build clean test

build:
	jbuilder build lib_test/test.exe

test:
	jbuilder runtest

clean:
	rm -rf _build
