/**
This is an implementation in C of cobuild. See reference implementation in Rust:
https://github.com/cryptape/ckb-transaction-cobuild-poc/blob/main/ckb-transaction-cobuild/src/lib.rs
*/
// clang-format off
#define CKB_DECLARATION_ONLY
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MOLECULEC_C2_DECLARATION_ONLY
#define MOLECULEC2_VERSION 7002
#include "cobuild.h"
#include "molecule2_reader.h"
#include "cobuild_basic_mol2.h"

#include "blake2b_decl_only.h"
#include "ckb_consts.h"
#include "ckb_syscall_apis.h"
// clang-format on
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define BLAKE2B_BLOCK_SIZE 32

#define CHECK2(cond, code)                                               \
  do {                                                                   \
    if (!(cond)) {                                                       \
      printf("error at %s:%d, error code %d", __FILE__, __LINE__, code); \
      err = code;                                                        \
      ASSERT(0);                                                         \
      goto exit;                                                         \
    }                                                                    \
  } while (0)

#define CHECK(_code)                                                     \
  do {                                                                   \
    int code = (_code);                                                  \
    if (code != 0) {                                                     \
      printf("error at %s:%d, error code %d", __FILE__, __LINE__, code); \
      err = code;                                                        \
      ASSERT(0);                                                         \
      goto exit;                                                         \
    }                                                                    \
  } while (0)

enum CobuildErrorCode {
  // cobuild error code is from 110
  ERROR_GENERAL = 110,
  ERROR_HASH,
  ERROR_NONEMPTY_WITNESS,
  ERROR_SIGHASHALL_DUP,
  ERROR_SIGHASHALL_NOSEAL,
  ERROR_MESSAGE,
  ERROR_TYPESCRIPT_MISSING,
  ERROR_SEAL,
  ERROR_FLOW,
};

enum WitnessLayoutId {
  WitnessLayoutSighashAll = 4278190081,
  WitnessLayoutSighashAllOnly = 4278190082,
  WitnessLayoutOtx = 4278190083,
  WitnessLayoutOtxStart = 4278190084,
};

enum MessageCalculationFlow {
  MessageCalculationFlowBlake2b = 0,
};

const char *PERSONAL_SIGHASH_ALL = "ckb-tcob-sighash";
const char *PERSONAL_SIGHASH_ALL_ONLY = "ckb-tcob-sgohash";
const char *PERSONAL_OTX = "ckb-tcob-otxhash";

#define MAX_TYPESCRIPT_COUNT 512

/*
  The seal cursor uses this data source. So the lifetime of data source should
  be long enough.
 */
static uint8_t g_cobuild_seal_data_source[DEFAULT_DATA_SOURCE_LENGTH];

#ifdef CKB_C_STDLIB_PRINTF

static void bin_to_hex(const uint8_t *source, uint8_t *dest, size_t len) {
  const static uint8_t HEX_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  for (int i = 0; i < len; i++) {
    dest[i * 2] = HEX_TABLE[source[i] >> 4];
    dest[i * 2 + 1] = HEX_TABLE[source[i] & 0x0F];
  }
}

void print_raw_data(const char *name, uint8_t *data, size_t len) {
  uint8_t str[924] = {0};
  const int limit = (sizeof(str) - 1) / 2;
  if (len > limit) {
    printf("The data length (%d) is too long, truncated to %d", len, limit);
    len = limit;
  }
  bin_to_hex(data, str, len);
  printf("%s(len=%d): %s", name, len, str);
}

void print_cursor(const char *name, mol2_cursor_t cursor) {
  uint8_t data[256] = {0};
  uint32_t read_len = mol2_read_at(&cursor, data, sizeof(data));
  if (read_len >= sizeof(data)) {
    printf("the cursor length (%d) is too long, truncated to %d", cursor.size,
           read_len);
  }
  print_raw_data(name, data, MIN(read_len, sizeof(data)));
}

// After being enabled, there will be a lot of logs.
#define BLAKE2B_UPDATE blake2b_update_debug
// #define BLAKE2B_UPDATE blake2b_update
int blake2b_update_debug(blake2b_state *S, const void *pin, size_t inlen) {
  blake2b_update(S, pin, inlen);
  print_raw_data("blake2b_update: ", (uint8_t *)pin, inlen);
  return 0;
}

#else

void print_raw_data(const char *name, uint8_t *data, size_t len) {}
void print_cursor(const char *name, mol2_cursor_t cursor) {}
#define BLAKE2B_UPDATE blake2b_update

#endif

static void store32(void *dst, uint32_t w) {
  uint8_t *p = (uint8_t *)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
}

int ckb_blake2b_init_personal(blake2b_state *S, size_t outlen,
                              const char *personal) {
  blake2b_param P[1];

  if ((!outlen) || (outlen > BLAKE2B_OUTBYTES)) return -1;

  P->digest_length = (uint8_t)outlen;
  P->key_length = 0;
  P->fanout = 1;
  P->depth = 1;
  store32(&P->leaf_length, 0);
  store32(&P->node_offset, 0);
  store32(&P->xof_length, 0);
  P->node_depth = 0;
  P->inner_length = 0;
  memset(P->reserved, 0, sizeof(P->reserved));
  memset(P->salt, 0, sizeof(P->salt));
  memset(P->personal, 0, sizeof(P->personal));
  for (int i = 0; i < BLAKE2B_PERSONALBYTES; ++i) {
    (P->personal)[i] = personal[i];
  }
  return blake2b_init_param(S, P);
}

int new_sighash_all_blake2b(blake2b_state *S) {
  return ckb_blake2b_init_personal(S, 32, PERSONAL_SIGHASH_ALL);
}

int new_sighash_all_only_blake2b(blake2b_state *S) {
  return ckb_blake2b_init_personal(S, 32, PERSONAL_SIGHASH_ALL_ONLY);
}

int new_otx_blake2b(blake2b_state *S) {
  return ckb_blake2b_init_personal(S, 32, PERSONAL_OTX);
}

// for lock script with message, the other witness in script group except first
// one should be empty
int ckb_check_others_in_group() {
  int err = ERROR_GENERAL;
  for (size_t index = 1;; index++) {
    uint64_t witness_len = 0;
    err = ckb_load_witness(0, &witness_len, 0, index, CKB_SOURCE_GROUP_INPUT);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      err = CKB_SUCCESS;
      break;
    }
    CHECK(err);
    // tested by test_non_empty_witness
    CHECK2(witness_len == 0, ERROR_NONEMPTY_WITNESS);
  }

exit:
  return err;
}

typedef uint32_t(read_from_t)(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                              uint32_t offset);

static uint32_t read_from_witness(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                                  uint32_t offset) {
  int err = ERROR_GENERAL;
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

void ckb_new_cursor(mol2_cursor_t *cursor, uint32_t total_len,
                    read_from_t read_from, uint8_t *data_source,
                    uint32_t cache_len, size_t index, size_t source) {
  cursor->offset = 0;
  cursor->size = (uint32_t)total_len;

  mol2_data_source_t *ptr = (mol2_data_source_t *)data_source;

  ptr->read = read_from;
  ptr->total_size = total_len;
  ptr->args[0] = index;
  ptr->args[1] = source;

  ptr->cache_size = 0;
  ptr->start_point = 0;
  ptr->max_cache_size = cache_len;

  cursor->data_source = ptr;
}

int ckb_new_witness_cursor(mol2_cursor_t *cursor, uint8_t *data_source,
                           uint32_t cache_len, size_t index, size_t source) {
  int err = ERROR_GENERAL;
  uint64_t len = 0;
  err = ckb_load_witness(0, &len, 0, index, source);
  CHECK(err);
  ckb_new_cursor(cursor, len, read_from_witness, data_source, cache_len, index,
                 source);

exit:
  return err;
}

int ckb_hash_cursor(blake2b_state *ctx, mol2_cursor_t cursor) {
  // one batch to drain whole cache perfectly
  // tested by test_input_cell_data_size_0
  //           test_input_cell_data_size_1
  //           test_input_cell_data_size_2048
  //           test_input_cell_data_size_2049
  //           test_input_cell_data_size_500k
  uint8_t batch[MAX_CACHE_SIZE];
  while (true) {
    uint32_t read_len = mol2_read_at(&cursor, batch, sizeof(batch));
    BLAKE2B_UPDATE(ctx, batch, read_len);
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

static uint32_t try_union_unpack_id(const mol2_cursor_t *cursor, uint32_t *id) {
  uint32_t len = mol2_read_at(cursor, (uint8_t *)id, 4);
  if (len != 4) {
    // tested by:
    //  tested_by_no_cobuild_append_sighash_all
    //  tested_by_insert_witness_less_4_before_sighashall
    return MOL2_ERR_DATA;
  }
  return CKB_SUCCESS;
}

int ckb_fetch_message(bool *has_message, mol2_cursor_t *message_cursor,
                      uint8_t *data_source, size_t cache_len) {
  int err = ERROR_GENERAL;
  *has_message = false;
  for (size_t index = 0;; index++) {
    uint32_t id = 0;
    uint64_t len = sizeof(id);
    err = ckb_load_witness(&id, &len, 0, index, CKB_SOURCE_INPUT);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      err = 0;
      break;
    }
    CHECK(err);
    if (len >= sizeof(id) && id == WitnessLayoutSighashAll) {
      // tested by:
      //  tested_by_sighashall_dup
      CHECK2(!*has_message, ERROR_SIGHASHALL_DUP);
      *has_message = true;
      mol2_cursor_t cursor = {0};
      err = ckb_new_witness_cursor(&cursor, data_source, cache_len, index,
                                   CKB_SOURCE_INPUT);
      CHECK(err);
      mol2_union_t uni = mol2_union_unpack(&cursor);
      /* See molecule defintion, the index is 0:
      table SighashAll {
        message: Message,
        seal: Bytes,
      }
      */
      *message_cursor = mol2_table_slice_by_index(&uni.cursor, 0);
    } else {
      // there are some possibilities:
      // 1. an invalid witness (e.g. empty)
      // 2. WitnessArgs
      // 3. Other cobuild WitnessLayout(e.g. SighashAllOnly)
      // tested by:
      //  tested_by_append_witnessed_less_than_4
      //  tested_by_append_witnessargs
      //  tested_by_append_other_witnesslayout
    }
  }
exit:
  return err;
}

int ckb_fetch_seal(mol2_cursor_t *seal_cursor) {
  int err = ERROR_GENERAL;
  mol2_cursor_t cursor;
  err = ckb_new_witness_cursor(&cursor, g_cobuild_seal_data_source,
                               MAX_CACHE_SIZE, 0, CKB_SOURCE_GROUP_INPUT);
  CHECK(err);
  uint32_t id = 0;
  err = try_union_unpack_id(&cursor, &id);
  // when error occurs here, it might be a WitnessArgs layout. It shouldn't be
  // cobuild and returns early.
  CHECK(err);
  if (id == WitnessLayoutSighashAll) {
    mol2_union_t uni = mol2_union_unpack(&cursor);
    /* See molecule defintion, the index is 1:
    table SighashAll {
      message: Message,
      seal: Bytes,
    }
    */
    *seal_cursor = mol2_table_slice_by_index(&uni.cursor, 1);
  } else if (id == WitnessLayoutSighashAllOnly) {
    /* See molecule defintion, the index is 0:
    table SighashAllOnly {
      seal: Bytes,
    }
    tested by test_sighash_all_only
  */
    mol2_union_t uni = mol2_union_unpack(&cursor);
    *seal_cursor = mol2_table_slice_by_index(&uni.cursor, 0);
  } else {
    // the union id should be SighashAll or SighashAllOnly. otherwise, it fails
    // and mark it as non cobuild.
    // tested by test_wrong_union_id
    printf("error in fetch_seal, id = %u", id);
    CHECK2(false, ERROR_SIGHASHALL_NOSEAL);
  }

exit:
  return err;
}

int ckb_generate_signing_message_hash(bool has_message,
                                      mol2_cursor_t message_cursor,
                                      uint8_t *signing_message_hash) {
  int err = 0;
  // this data source is on stack. When this function returns, all cursors bound
  // to this buffer become invalid.
  uint8_t data_source[DEFAULT_DATA_SOURCE_LENGTH];

  blake2b_state ctx;
  size_t count = 0;
  // use different hash based on message
  if (has_message) {
    // tested by test_input_cell_data_size_0
    new_sighash_all_blake2b(&ctx);
    ckb_hash_cursor(&ctx, message_cursor);
    count += message_cursor.size;
  } else {
    // tested by:
    //  tested_by_no_has_message
    new_sighash_all_only_blake2b(&ctx);
  }

  // hash tx hash
  uint8_t tx_hash[BLAKE2B_BLOCK_SIZE];
  uint64_t tx_hash_len = sizeof(tx_hash);
  err = ckb_load_tx_hash(tx_hash, &tx_hash_len, 0);
  CHECK(err);
  BLAKE2B_UPDATE(&ctx, tx_hash, sizeof(tx_hash));
  count += 32;

  // hash input cell and data
  size_t index = 0;
  for (;; index++) {
    // default input size is 44 bytes
    uint8_t input[128];
    uint64_t input_len = sizeof(input);
    err = ckb_load_input(input, &input_len, 0, index, CKB_SOURCE_INPUT);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      err = 0;
      break;
    }
    CHECK(err);
    BLAKE2B_UPDATE(&ctx, input, input_len);
    count += input_len;

    uint64_t cell_data_len = 0;
    err = ckb_load_cell_data(0, &cell_data_len, 0, index, CKB_SOURCE_INPUT);
    CHECK(err);
    mol2_cursor_t cell_data_cursor;
    ckb_new_cursor(&cell_data_cursor, cell_data_len, read_from_cell_data,
                   data_source, MAX_CACHE_SIZE, index, CKB_SOURCE_INPUT);
    // only hash as uint32_t. 4 bytes is enough
    BLAKE2B_UPDATE(&ctx, &cell_data_len, 4);
    count += 4;
    err = ckb_hash_cursor(&ctx, cell_data_cursor);
    count += cell_data_cursor.size;
    CHECK(err);
  }
  size_t input_len = index;
  // hash remaining witnesses
  for (size_t index = input_len;; index++) {
    uint64_t witness_len = 0;
    err = ckb_load_witness(0, &witness_len, 0, index, CKB_SOURCE_INPUT);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      err = 0;
      break;
    }
    CHECK(err);
    mol2_cursor_t witness_cursor;
    ckb_new_cursor(&witness_cursor, witness_len, read_from_witness, data_source,
                   MAX_CACHE_SIZE, index, CKB_SOURCE_INPUT);
    // only hash as uint32_t. 4 bytes is enough
    BLAKE2B_UPDATE(&ctx, &witness_len, 4);
    count += 4;
    err = ckb_hash_cursor(&ctx, witness_cursor);
    count += witness_cursor.size;
    CHECK(err);
  }
  blake2b_final(&ctx, signing_message_hash, BLAKE2B_BLOCK_SIZE);
  printf("ckb_generate_signing_message_hash total hashed %d bytes", count);

exit:
  return err;
}

static int hash_cmp(const void *h1, const void *h2) {
  return memcmp(h1, h2, BLAKE2B_BLOCK_SIZE);
}

static int collect_type_script_hash(uint8_t *type_script_hash,
                                    uint32_t *type_script_hash_count,
                                    size_t source) {
  int err = 0;
  size_t i = 0;
  while (1) {
    uint8_t hash[BLAKE2B_BLOCK_SIZE] = {0};
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    err = ckb_load_cell_by_field(hash, &len, 0, i, source,
                                 CKB_CELL_FIELD_TYPE_HASH);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      err = 0;
      break;
    }
    if (err == CKB_ITEM_MISSING) {
      i += 1;
      continue;
    }
    CHECK(err);
    CHECK2(*type_script_hash_count < MAX_TYPESCRIPT_COUNT, ERROR_GENERAL);
    memcpy(&type_script_hash[(*type_script_hash_count) * BLAKE2B_BLOCK_SIZE],
           hash, BLAKE2B_BLOCK_SIZE);
    (*type_script_hash_count)++;
    i += 1;
  }
exit:
  return err;
}

// For each action in the message, ensure a corresponding type script hash
// (including input/output) matches the action.script_hash. Let A be the set of
// action.script_hash, and B be the set of all input/output script hashes; A ∈ B
// should be satisfied.
static int check_type_script_existing(mol2_cursor_t message) {
  int err = 0;
  // cache all type script hashes in input/output cells
  uint8_t type_script_hash[BLAKE2B_BLOCK_SIZE * MAX_TYPESCRIPT_COUNT] = {0};
  uint32_t type_script_hash_count = 0;

  err = collect_type_script_hash(type_script_hash, &type_script_hash_count,
                                 CKB_SOURCE_INPUT);
  CHECK(err);
  err = collect_type_script_hash(type_script_hash, &type_script_hash_count,
                                 CKB_SOURCE_OUTPUT);
  CHECK(err);
  // sort for fast searching
  qsort(type_script_hash, type_script_hash_count, BLAKE2B_BLOCK_SIZE, hash_cmp);

  MessageType msg = make_Message(&message);
  ActionVecType actions = msg.t->actions(&msg);
  uint32_t len = actions.t->len(&actions);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    ActionType action = actions.t->get(&actions, i, &existing);
    CHECK2(existing, ERROR_GENERAL);
    mol2_cursor_t hash = action.t->script_hash(&action);
    uint8_t hash_buff[BLAKE2B_BLOCK_SIZE] = {0};
    uint32_t len = mol2_read_at(&hash, hash_buff, BLAKE2B_BLOCK_SIZE);
    CHECK2(len == BLAKE2B_BLOCK_SIZE, ERROR_MESSAGE);
    void *found = bsearch(hash_buff, type_script_hash, type_script_hash_count,
                          BLAKE2B_BLOCK_SIZE, hash_cmp);
    CHECK2(found != NULL, ERROR_TYPESCRIPT_MISSING);
  }

exit:
  return err;
}

// Parse the `original_seal` and return underlying seal after adjustment. The
// first byte of `seal` is considered as an id of message calculation flow.
static int parse_seal(const mol2_cursor_t original_seal, mol2_cursor_t *seal,
                      uint8_t *message_calculation_flow) {
  int err = 0;
  uint32_t prefix_length = 1 + MOL2_NUM_T_SIZE;
  uint8_t prefix[1 + MOL2_NUM_T_SIZE] = {0};

  uint32_t len = mol2_read_at(&original_seal, prefix, prefix_length);
  CHECK2(len == prefix_length, ERROR_SEAL);
  *message_calculation_flow = prefix[MOL2_NUM_T_SIZE];
  *seal = original_seal;
  mol2_add_offset(seal, prefix_length);
  mol2_sub_size(seal, prefix_length);
  mol2_validate(seal);

exit:
  return err;
}

int ckb_parse_message(uint8_t *signing_message_hash, mol2_cursor_t *seal) {
  int err = ERROR_GENERAL;

  bool has_message = false;
  mol2_cursor_t message;
  // the message cursor requires longer lifetime of data_source
  uint8_t data_source[DEFAULT_DATA_SOURCE_LENGTH];
  // step 8.a, 8.b
  err = ckb_fetch_message(&has_message, &message, data_source, MAX_CACHE_SIZE);
  CHECK(err);
  if (has_message) {
    print_cursor("message", message);
    // step 8.c
    err = check_type_script_existing(message);
    CHECK(err);
  }

  mol2_cursor_t original_seal = {0};
  // step 8.d
  // step 8.f
  err = ckb_fetch_seal(&original_seal);
  CHECK(err);
  print_cursor("seal", original_seal);

  // step 8.e
  err = ckb_check_others_in_group();
  // tested by test_non_empty_witness
  CHECK(err);

  // support more message calculation flows base on the first byte of seal
  uint8_t message_calculation_flow = 0;
  err = parse_seal(original_seal, seal, &message_calculation_flow);
  CHECK(err);

  if (message_calculation_flow == MessageCalculationFlowBlake2b) {
    // step 8.g
    err = ckb_generate_signing_message_hash(has_message, message,
                                            signing_message_hash);
    CHECK(err);
    print_raw_data("signing_message_hash", signing_message_hash,
                   BLAKE2B_BLOCK_SIZE);
  } else {
    // we can add more message calculation flows in the further, based on the
    // first byte of seal
    CHECK2(false, ERROR_FLOW);
  }

exit:
  return err;
}
