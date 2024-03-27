/*
 * This file contains handy utilities for molecule-c2. Ideally most of
 * this file should be part of molecule-c2 itself.
 */

#ifndef MOL2_UTILS
#define MOL2_UTILS

#include "blake2b.h"
#include "ckb_consts.h"
#include "ckb_syscall_apis.h"
#include "molecule2_reader.h"

// Given a data source, this macro extracts the start of cache buffer
#define MOL2_CACHE_PTR(data_source) \
  (((mol2_data_source_t *)(data_source))->cache)

typedef uint32_t(read_from_t)(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                              uint32_t offset);

static uint32_t read_from_witness(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                                  uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_load_witness(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

static uint32_t read_from_cell_data(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                                    uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_load_cell_data(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

static uint32_t read_from_cell(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                               uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_load_cell(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

static uint32_t read_from_tx(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                             uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_load_transaction(ptr, &output_len, offset);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

static uint32_t read_from_script(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                                 uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_load_script(ptr, &output_len, offset);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

static void ckb_new_cursor_with_data(mol2_cursor_t *cursor, uint32_t total_len,
                                     read_from_t read_from,
                                     uint8_t *data_source, uint32_t cache_len,
                                     size_t index, size_t source,
                                     uint32_t cached_size) {
  cursor->offset = 0;
  cursor->size = (uint32_t)total_len;

  mol2_data_source_t *ptr = (mol2_data_source_t *)data_source;

  ptr->read = read_from;
  ptr->total_size = total_len;
  ptr->args[0] = index;
  ptr->args[1] = source;

  ptr->cache_size = cached_size;
  ptr->start_point = 0;
  ptr->max_cache_size = cache_len;

  cursor->data_source = ptr;
}

static int ckb_new_witness_cursor(mol2_cursor_t *cursor, uint8_t *data_source,
                                  uint32_t cache_len, size_t index,
                                  size_t source) {
  int err;

  // Use a single syscall to fetch cached data and total length
  uint64_t len = cache_len;
  err = ckb_load_witness(MOL2_CACHE_PTR(data_source), &len, 0, index, source);
  if (err != 0) {
    return err;
  }
  uint32_t cache_size = (uint32_t)len;
  if (cache_size > cache_len) {
    cache_size = cache_len;
  }
  ckb_new_cursor_with_data(cursor, len, read_from_witness, data_source,
                           cache_len, index, source, cache_size);

  return 0;
}

typedef int(cursor_accessor_t)(const uint8_t *data, size_t len, void *context);
static int ckb_access_cursor(mol2_cursor_t cursor, cursor_accessor_t accessor,
                             void *context) {
  int err = 0;
  uint8_t batch[MAX_CACHE_SIZE];
  while (true) {
    uint32_t read_len = mol2_read_at(&cursor, batch, sizeof(batch));
    err = accessor(batch, read_len, context);
    if (err != 0) {
      return err;
    }
    // adjust cursor
    mol2_add_offset(&cursor, read_len);
    mol2_sub_size(&cursor, read_len);
    mol2_validate(&cursor);
    if (cursor.size == 0) {
      break;
    }
  }
  return 0;
}

#ifndef BLAKE2B_UPDATE
#define BLAKE2B_UPDATE blake2b_update
#endif

static int _ckb_cursor_blake2b_hasher(const uint8_t *data, size_t len,
                                      void *context) {
  blake2b_state *state = (blake2b_state *)context;
  BLAKE2B_UPDATE(state, data, len);
  return 0;
}

static int ckb_hash_cursor(blake2b_state *ctx, mol2_cursor_t cursor) {
  // one batch to drain whole cache perfectly
  // tested by test_input_cell_data_size_0
  //           test_input_cell_data_size_1
  //           test_input_cell_data_size_2048
  //           test_input_cell_data_size_2049
  //           test_input_cell_data_size_500k
  return ckb_access_cursor(cursor, _ckb_cursor_blake2b_hasher, ctx);
}

static int ckb_compare_cursor(mol2_cursor_t a, mol2_cursor_t b, int *result) {
  if (a.size < b.size) {
    *result = -1;
    return 0;
  } else if (a.size > b.size) {
    *result = 1;
    return 0;
  }

  uint8_t batch_a[MAX_CACHE_SIZE];
  uint8_t batch_b[MAX_CACHE_SIZE];
  while (true) {
    uint32_t read_len_a = mol2_read_at(&a, batch_a, sizeof(batch_a));
    uint32_t read_len_b = mol2_read_at(&b, batch_b, sizeof(batch_b));
    if (read_len_a != read_len_b) {
      return MOL2_ERR_DATA;
    }
    int ret = memcmp(batch_a, batch_b, read_len_a);
    if (ret != 0) {
      *result = ret;
      return 0;
    }

    // adjust cursors
    mol2_add_offset(&a, read_len_a);
    mol2_sub_size(&a, read_len_a);
    mol2_validate(&a);
    mol2_add_offset(&b, read_len_b);
    mol2_sub_size(&b, read_len_b);
    mol2_validate(&b);
    if (a.size == 0) {
      break;
    }
  }

  *result = 0;
  return 0;
}

static int try_union_unpack_id(const mol2_cursor_t *cursor, uint32_t *id) {
  uint32_t len = mol2_read_at(cursor, (uint8_t *)id, 4);
  if (len != 4) {
    // tested by:
    //  tested_by_no_cobuild_append_sighash_all
    //  tested_by_insert_witness_less_4_before_sighashall
    return MOL2_ERR_DATA;
  }
  return CKB_SUCCESS;
}

#ifndef MOL2_UTILS_CACHE_TX_SIZE
#define MOL2_UTILS_CACHE_TX_SIZE 65536
#endif

#ifndef MOL2_UTILS_CACHE_SCRIPT_SIZE
#define MOL2_UTILS_CACHE_SCRIPT_SIZE 1024
#endif

typedef struct {
  uint8_t tx_source[MOL2_DATA_SOURCE_LEN(MOL2_UTILS_CACHE_TX_SIZE)];
  mol2_cursor_t tx_cursor;
  TransactionType tx;

  uint8_t
      current_script_source[MOL2_DATA_SOURCE_LEN(MOL2_UTILS_CACHE_SCRIPT_SIZE)];
  mol2_cursor_t current_script_cursor;
  ScriptType current_script;

  uint8_t tx_hash[32];
  uint8_t current_script_hash[32];

  void *script_specific_data;
} Env;

static int ckb_env_initialize(Env *env) {
  int err;
  {
    uint64_t tx_len = MOL2_UTILS_CACHE_TX_SIZE;
    err = ckb_load_transaction(MOL2_CACHE_PTR(env->tx_source), &tx_len, 0);
    if (err != 0) {
      return err;
    }
    uint32_t cache_size = (uint32_t)tx_len;
    if (cache_size > MOL2_UTILS_CACHE_TX_SIZE) {
      cache_size = MOL2_UTILS_CACHE_TX_SIZE;
    }

    ckb_new_cursor_with_data(&env->tx_cursor, tx_len, read_from_tx,
                             env->tx_source, MOL2_UTILS_CACHE_TX_SIZE, 0, 0,
                             cache_size);

    env->tx = make_Transaction(&env->tx_cursor);
  }

  {
    uint64_t script_len = MOL2_UTILS_CACHE_SCRIPT_SIZE;
    err = ckb_load_script(MOL2_CACHE_PTR(env->current_script_source),
                          &script_len, 0);
    if (err != 0) {
      return err;
    }
    uint32_t cache_size = (uint32_t)script_len;
    if (cache_size > MOL2_UTILS_CACHE_SCRIPT_SIZE) {
      cache_size = MOL2_UTILS_CACHE_SCRIPT_SIZE;
    }

    ckb_new_cursor_with_data(&env->current_script_cursor, script_len,
                             read_from_script, env->current_script_source,
                             MOL2_UTILS_CACHE_SCRIPT_SIZE, 0, 0,
                             MOL2_UTILS_CACHE_SCRIPT_SIZE);

    env->current_script = make_Script(&env->current_script_cursor);
  }

  {
    uint64_t tx_hash_len = 32;
    err = ckb_load_tx_hash(env->tx_hash, &tx_hash_len, 0);
    if (err != 0) {
      return err;
    }
    if (tx_hash_len != 32) {
      return MOL2_ERR_DATA;
    }
  }

  {
    uint64_t script_hash_len = 32;
    err = ckb_load_script_hash(env->current_script_hash, &script_hash_len, 0);
    if (err != 0) {
      return err;
    }
    if (script_hash_len != 32) {
      return MOL2_ERR_DATA;
    }
  }

  env->script_specific_data = NULL;

  return 0;
}

static inline mol2_cursor_t mol2_cursor_slice(const mol2_cursor_t *cur,
                                              uint32_t offset,
                                              uint32_t new_size) {
  uint32_t shrinked_size;
  // This way we can ensure that the new size will be no larger than original
  // cursor
  if (__builtin_sub_overflow(cur->size, new_size, &shrinked_size)) {
    MOL2_PANIC(MOL2_ERR_OVERFLOW);
  }
  mol2_cursor_t res = *cur;
  mol2_add_offset(&res, offset);
  mol2_sub_size(&res, shrinked_size);
  mol2_validate(&res);
  return res;
}

static inline mol2_cursor_t mol2_cursor_slice_start(const mol2_cursor_t *cur,
                                                    uint32_t offset) {
  mol2_cursor_t res = *cur;
  mol2_add_offset(&res, offset);
  mol2_sub_size(&res, offset);
  mol2_validate(&res);
  return res;
}

#endif /* MOL2_UTILS */
