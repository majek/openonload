SUBDIRS	:= internal_tests

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

