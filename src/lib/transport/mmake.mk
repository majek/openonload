SUBDIRS	:= ip common unix
DRIVER_SUBDIRS := ip


all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

