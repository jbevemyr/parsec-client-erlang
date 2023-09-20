PROJECT = parsec
PROJECT_DESCRIPTION = Erlang parsec client
PROJECT_VERSION = 0.1

BUILD_DEPS = parsec_operations gpb

dep_parsec_operations = git https://github.com/parallaxsecond/parsec-operations.git \
		87cef311988fccf0d766fe778d0c7aed856293d1

PARSEC_PROTO_SRC_FILES = $(wildcard $(DEPS_DIR)/parsec_operations/protobuf/*.proto)
PARSEC_PROTO_ERL_FILES = $(patsubst $(DEPS_DIR)/parsec_operations/protobuf/%.proto, src/%.erl, $(PARSEC_PROTO_SRC_FILES))

src/%.erl: $(DEPS_DIR)/parsec_operations/protobuf/%.proto
	$(DEPS_DIR)/gpb/bin/protoc-erl -maps -pkgs -strbin -o src -I$(DEPS_DIR)/parsec_operations/protobuf $<

include erlang.mk

$(PROJECT).d:: $(PARSEC_PROTO_ERL_FILES)

clean::
	rm -rf $(PARSEC_PROTO_ERL_FILES)

