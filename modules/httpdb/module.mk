#
# module.mk
#
# Copyright (C) 2013 Metaswitch Networks
#

MOD		:= httpdb
$(MOD)_SRCS	+= httpdb.c
$(MOD)_LFLAGS	+= -lcurl -ljsoncpp

CFLAGS		+= -I$(SYSROOT)/local/include

include mk/mod.mk
