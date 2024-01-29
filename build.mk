ifeq ($(OSNAME),Linux)
CD := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
NETMAP_DIR ?= $(CD)/netmap
CFLAGS += -D_GNU_SOURCE
CFLAGS += -I$(NETMAP_DIR)/libnetmap -I$(NETMAP_DIR)/sys
LDFLAGS += -L$(NETMAP_DIR)/build-libnetmap
endif
LDFLAGS += -lnetmap -lpthread
