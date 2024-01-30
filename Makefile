TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -I deps/secp256k1/src -I deps/secp256k1 -I deps/ckb-c-std-lib -I deps/ckb-c-std-lib/libc -I deps/ckb-c-std-lib/molecule -I c -I build -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g
LDFLAGS := -nostdlib -nostartfiles -fno-builtin -Wl,-static -Wl,--gc-sections
SECP256K1_SRC_20210801 := deps/secp256k1-20210801/src/ecmult_static_pre_context.h


OMNI_LOCK_CFLAGS :=$(subst ckb-c-std-lib,ckb-c-stdlib-20210801,$(CFLAGS)) -I deps/sparse-merkle-tree/c
OMNI_LOCK_CFLAGS := $(subst secp256k1,secp256k1-20210801,$(OMNI_LOCK_CFLAGS))
# enable log
# OMNI_LOCK_CFLAGS += -DCKB_C_STDLIB_PRINTF -DCKB_C_STDLIB_PRINTF_BUFFER_SIZE=1024


PROTOCOL_HEADER := c/blockchain.h
PROTOCOL_SCHEMA := c/blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol
MOLC := moleculec
MOLC_VERSION := 0.7.0

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3
CLANG_FORMAT_DOCKER := kason223/clang-format@sha256:3cce35b0400a7d420ec8504558a02bdfc12fd2d10e40206f140c4545059cd95d

all: build/omni_lock build/always_success

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"


build/always_success: c/always_success.c
	$(CC) $(OMNI_LOCK_CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/secp256k1_data_info_20210801.h: build/dump_secp256k1_data_20210801
	$<

build/dump_secp256k1_data_20210801: c/dump_secp256k1_data_20210801.c $(SECP256K1_SRC_20210801)
	mkdir -p build
	gcc -I deps/secp256k1-20210801/src -I deps/secp256k1-20210801 -o $@ $<


$(SECP256K1_SRC_20210801):
	cd deps/secp256k1-20210801 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h


build/impl.o: deps/ckb-c-std-lib/libc/src/impl.c
	$(CC) -c $(filter-out -DCKB_DECLARATION_ONLY, $(CFLAGS_MBEDTLS)) $(LDFLAGS_MBEDTLS) -o $@ $^

${PROTOCOL_SCHEMA}:
	curl -L -o $@ ${PROTOCOL_URL}

ALL_C_SOURCE := $(wildcard c/omni_lock.c c/omni_lock_acp.h c/omni_lock_time_lock.h \
	tests/omni_lock/omni_lock_sim.c tests/omni_lock/ckb_syscall_omni_lock_sim.h tests/omni_lock/omni_lock_supply.h\
	c/blake2b_decl_only.h c/cobuild.h c/cobuild.c)

fmt:
	docker run --rm -v `pwd`:/code ${CLANG_FORMAT_DOCKER} bash -c "cd code && clang-format -i -style=Google $(ALL_C_SOURCE)"
	git diff --exit-code $(ALL_C_SOURCE)

mol:
	make omni_lock_mol
	make cobuild_mol

c/xudt_rce_mol.h: c/xudt_rce.mol
	${MOLC} --language c --schema-file $< > $@

c/xudt_rce_mol2.h: c/xudt_rce.mol
	moleculec --language - --schema-file c/xudt_rce.mol --format json > build/blockchain_mol2.json
	moleculec-c2 --input build/blockchain_mol2.json | clang-format -style=Google > c/xudt_rce_mol2.h

omni_lock_mol:
	${MOLC} --language rust --schema-file c/omni_lock.mol | rustfmt > tests/omni_lock_rust/src/omni_lock.rs
	${MOLC} --language c --schema-file c/omni_lock.mol > c/omni_lock_mol.h
	${MOLC} --language - --schema-file c/omni_lock.mol --format json > build/omni_lock_mol2.json
	moleculec-c2 --input build/omni_lock_mol2.json | clang-format -style=Google > c/omni_lock_mol2.h

build/cobuild.o: c/cobuild.c c/cobuild.h
	$(CC) -c $(OMNI_LOCK_CFLAGS) -o $@ $<

build/omni_lock.o: c/omni_lock.c c/omni_lock_supply.h c/omni_lock_acp.h c/secp256k1_lock.h build/secp256k1_data_info_20210801.h $(SECP256K1_SRC_20210801) c/ckb_identity.h
	$(CC) -c $(OMNI_LOCK_CFLAGS) -o $@ $<

build/omni_lock: build/omni_lock.o build/cobuild.o
	$(CC) $(LDFLAGS) -o $@ $^
	cp $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

cobuild_mol:
	${MOLC} --language rust --schema-file c/basic.mol | rustfmt > tests/omni_lock_rust/src/schemas/basic.rs
	${MOLC} --language rust --schema-file c/top_level.mol | rustfmt > tests/omni_lock_rust/src/schemas/top_level.rs
	${MOLC} --language - --schema-file c/basic.mol --format json > build/cobuild_basic_mol2.json
	moleculec-c2 --input build/cobuild_basic_mol2.json | clang-format -style=Google > c/cobuild_basic_mol2.h

clean:
	rm -rf build/secp256k1_data_info_20210801.h build/dump_secp256k1_data_20210801
	rm -rf build/secp256k1_data_20210801
	rm -rf build/*.debug
	rm -f build/omni_lock
	rm -f build/*.o
	cd deps/secp256k1-20210801 && [ -f "Makefile" ] && make clean

install-tools:
	if [ ! -x "$$(command -v "${MOLC}")" ] \
			|| [ "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" != "${MOLC_VERSION}" ]; then \
		cargo install --force --version "${MOLC_VERSION}" "${MOLC}"; \
	fi

dist: clean all

.PHONY: all all-via-docker dist clean package-clean package publish
