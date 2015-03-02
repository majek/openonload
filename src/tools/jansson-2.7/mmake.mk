
LIBS := libjansson.a

libjansson.a:
	cp -a $(TOP)/src/tools/jansson-2.7 .
	cd jansson-2.7 && \
	  autoreconf -i
	mkdir -p build
	cd build && \
	  ../jansson-2.7/configure && \
	  $(MAKE)
	cp build/src/.libs/libjansson.a .

all: $(LIBS)

clean:
	rm -rf jansson-2.7 build libjansson.a ltmain.sh
