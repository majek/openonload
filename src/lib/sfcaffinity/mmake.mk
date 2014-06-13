
TARGETS		:= libsfcaffinity.so
MMAKE_TYPE	:= DLL


all: $(TARGETS)

lib: $(TARGETS)

clean:
	@$(MakeClean)


lib%.so: %.o
	@(libs="-ldl"; $(MMakeLinkPreloadLib))
