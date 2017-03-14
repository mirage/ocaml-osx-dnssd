
.PHONY: build clean

build:
	jbuilder build lib_test/test.exe

clean:
	rm -rf _build
