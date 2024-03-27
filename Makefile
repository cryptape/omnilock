
TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -g -fPIC -O3 -fno-builtin \
		-nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections \
		-I deps/secp256k1/src -I deps/secp256k1 -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/libc \
		-I deps/ckb-c-stdlib/molecule -I c -I build -I deps/sparse-merkle-tree/c \
		-Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -Wno-array-bounds -Wno-stringop-overflow \
		-DCKB_C_STDLIB_PRINTF -DCKB_C_STDLIB_PRINTF_BUFFER_SIZE=1024

LDFLAGS := -nostdlib -nostartfiles -Wl,-static -Wl,--gc-sections

SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h

MOLC := moleculec
MOLC_VERSION := 0.7.0

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-jammy-20230214
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:d3f649ef8079395eb25a21ceaeb15674f47eaa2d8cc23adc8bcdae3d5abce6ec
CLANG_FORMAT_DOCKER := xujiandong/ckb-riscv-llvm-toolchain@sha256:6409ab0d3e335c74088b54f4f73252f4b3367ae364d5c7ca7acee82135f5af4d

all: build/omni_lock build/always_success

all-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

build/always_success: c/always_success.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: c/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc -I deps/secp256k1/src -I deps/secp256k1 -I deps/ckb-c-stdlib -o $@ $<


$(SECP256K1_SRC):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --enable-ecmult-static-precomputation --with-ecmult-window=6 --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

ALL_C_SOURCE := $(wildcard c/omni_lock.c c/omni_lock_acp.h c/omni_lock_time_lock.h \
	tests/omni_lock/omni_lock_sim.c tests/omni_lock/ckb_syscall_omni_lock_sim.h tests/omni_lock/omni_lock_supply.h\
	c/cobuild.h c/molecule2_verify.h mol2_utils.h)

fmt:
	docker run -u $(shell id -u):$(shell id -g) --rm -v `pwd`:/code ${CLANG_FORMAT_DOCKER} bash -c "cd code && clang-format -i -style='{BasedOnStyle: google, SortIncludes: false}' $(ALL_C_SOURCE)"
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

build/omni_lock: c/omni_lock.c c/omni_lock_supply.h c/omni_lock_acp.h build/secp256k1_data_info.h $(SECP256K1_SRC) \
				c/ckb_identity.h c/mol2_utils.h c/cobuild_basic_mol2.h c/molecule2_verify.h \
				c/cobuild.h c/mol2_utils.h c/molecule2_verify.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	cp $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

cobuild_mol:
	${MOLC} --language rust --schema-file c/basic.mol | rustfmt > tests/omni_lock_rust/src/schemas/basic.rs
	${MOLC} --language rust --schema-file c/top_level.mol | rustfmt > tests/omni_lock_rust/src/schemas/top_level.rs
	${MOLC} --language - --schema-file c/basic.mol --format json > build/cobuild_basic_mol2.json
	moleculec-c2 --input build/cobuild_basic_mol2.json | clang-format -style=Google > c/cobuild_basic_mol2.h
	${MOLC} --language - --schema-file c/top_level.mol --format json > build/cobuild_top_level_mol2.json
	moleculec-c2 --input build/cobuild_top_level_mol2.json | clang-format -style=Google > c/cobuild_top_level_mol2.h

clean: clean2
	rm -rf build/secp256k1_data_info.h build/dump_secp256k1_data
	rm -f build/secp256k1_data
	cd deps/secp256k1 && [ -f "Makefile" ] && make clean

clean2:
	rm -rf build/*.debug
	rm -f build/omni_lock
	rm -f build/*.o
	rm -f build/always_success
	
dist: clean all

.PHONY: all all-via-docker dist clean package-clean package publish
