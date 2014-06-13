
SUBDIRS		:= preload

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

