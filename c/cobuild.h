/** CKB Transaction Cobuild Helper Library
 * The `ckb_cobuild_entry` function serves as the primary entry point for
 * cobuild integration.
 *
 * To begin, a callback function for signature validation should be implemented:
 *
 * int lock_entry(const Env *env, const uint8_t *smh, mol2_cursor_t seal) {
 *     // Validate smh (signing message hash) against seal (signature)
 *     // Any legacy script code can be moved here
 * }
 *
 * Afterward, the `ckb_cobuild_entry` function is invoked:
 *
 * ckb_env_initialize(&env);
 *
 * bool cobuild_activated = false;
 * err = ckb_cobuild_entry(&env, omnilock_entry, &cobuild_activated);
 * if (err) {
 *     // Implement error handling code here
 *     ckb_exit(err);
 * }
 * printf("cobuild_activated = %d", cobuild_activated);
 * if (!cobuild_activated) {
 *     // Any legacy script code can be placed here
 *     // This may include reading witness, script arguments, validating
 *     // signatures, etc.
 * }
 */
#ifndef __COBUILD_H__
#define __COBUILD_H__

// clang-format off
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "molecule2_reader.h"
#include "mol2_utils.h"
#include "molecule2_reader.h"
#include "blockchain-api2.h"
#include "cobuild_basic_mol2.h"
#include "cobuild_top_level_mol2.h"
#include "molecule2_verify.h"

#include "blake2b.h"
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
#define MAX_SCRIPT_COUNT 512

#define CKB_COBUILD_CHECK2(cond, code)                                   \
  do {                                                                   \
    if (!(cond)) {                                                       \
      printf("error at %s:%d, error code %d", __FILE__, __LINE__, code); \
      err = code;                                                        \
      ASSERT(0);                                                         \
      goto exit;                                                         \
    }                                                                    \
  } while (0)

#define CKB_COBUILD_CHECK(_code)                                         \
  do {                                                                   \
    int code = (_code);                                                  \
    if (code != 0) {                                                     \
      printf("error at %s:%d, error code %d", __FILE__, __LINE__, code); \
      err = code;                                                        \
      ASSERT(0);                                                         \
      goto exit;                                                         \
    }                                                                    \
  } while (0)

#define CKB_COBUILD_CHECK_LOOP(err)    \
  if (err == CKB_INDEX_OUT_OF_BOUND) { \
    err = 0;                           \
    break;                             \
  }                                    \
  CKB_COBUILD_CHECK(err)

enum CobuildErrorCode {
  // cobuild error code is from 110
  COBUILD_ERROR_GENERAL = 110,
  COBUILD_ERROR_HASH,
  COBUILD_ERROR_NONEMPTY_WITNESS,
  COBUILD_ERROR_SIGHASHALL_DUP,
  COBUILD_ERROR_SIGHASHALL_NOSEAL,
  COBUILD_ERROR_MESSAGE,
  COBUILD_ERROR_TYPESCRIPT_MISSING,
  COBUILD_ERROR_SEAL,
  COBUILD_ERROR_FLOW,
  COBUILD_ERROR_OTX_START_DUP,
  COBUILD_ERROR_WRONG_OTX,
  COBUILD_ERROR_NOT_COBUILD,
  COBUILD_ERROR_NO_CALLBACK,
  COBUILD_ERROR_MOL2_UNEXPECTED,
  COBUILD_ERROR_OVERFLOW,
};

typedef int (*ScriptEntryType)(const Env *env,
                               const uint8_t *signing_message_hash,
                               mol2_cursor_t seal);

enum MessageCalculationFlow {
  MessageCalculationFlowBlake2b = 0,
};

typedef struct OtxStart {
  uint32_t start_input_cell;
  uint32_t start_output_cell;
  uint32_t start_cell_deps;
  uint32_t start_header_deps;
} OtxStart;

typedef struct Otx {
  uint32_t input_cells;
  uint32_t output_cells;
  uint32_t cell_deps;
  uint32_t header_deps;
} Otx;

const char *PERSONAL_SIGHASH_ALL = "ckb-tcob-sighash";
const char *PERSONAL_SIGHASH_ALL_ONLY = "ckb-tcob-sgohash";
const char *PERSONAL_OTX = "ckb-tcob-otxhash";

#ifdef CKB_C_STDLIB_PRINTF
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
// #define BLAKE2B_UPDATE blake2b_update_debug
#define BLAKE2B_UPDATE blake2b_update
int blake2b_update_debug(blake2b_state *S, const void *pin, size_t inlen) {
  blake2b_update(S, pin, inlen);
  print_raw_data("blake2b_update", (uint8_t *)pin, inlen);
  return 0;
}

#else

void print_raw_data(const char *name, const uint8_t *data, size_t len) {}
void print_cursor(const char *name, mol2_cursor_t cursor) {}
#define BLAKE2B_UPDATE blake2b_update

#endif

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

static inline int get_witness_layout(BytesVecType witnesses, uint32_t index,
                                     WitnessLayoutType *witness_layout) {
  bool existing = false;
  mol2_cursor_t witness = witnesses.t->get(&witnesses, index, &existing);
  if (!existing) {
    return COBUILD_ERROR_MOL2_UNEXPECTED;
  }

  WitnessLayoutType witness_layout2 = make_WitnessLayout(&witness);
  if (verify_WitnessLayout(&witness_layout2)) {
    return COBUILD_ERROR_GENERAL;
  }
  if (witness_layout != NULL) {
    *witness_layout = witness_layout2;
  }
  return 0;
}

// for lock script with message, the other witness in script group except first
// one should be empty
int ckb_check_others_in_group() {
  int err = COBUILD_ERROR_GENERAL;
  for (size_t index = 1;; index++) {
    uint64_t witness_len = 0;
    err = ckb_load_witness(0, &witness_len, 0, index, CKB_SOURCE_GROUP_INPUT);
    CKB_COBUILD_CHECK_LOOP(err);
    // tested by test_non_empty_witness
    CKB_COBUILD_CHECK2(witness_len == 0, COBUILD_ERROR_NONEMPTY_WITNESS);
  }

exit:
  return err;
}

int ckb_fetch_sighash_message(BytesVecType witnesses, MessageType *message) {
  int err = 0;
  bool has_message = false;
  uint32_t witness_len = witnesses.t->len(&witnesses);
  for (uint32_t index = 0; index < witness_len; index++) {
    WitnessLayoutType witness_layout = {0};
    if (get_witness_layout(witnesses, index, &witness_layout) == 0) {
      uint32_t id = witness_layout.t->item_id(&witness_layout);
      if (id == WitnessLayoutSighashAll) {
        // tested by:
        //  tested_by_sighashall_dup
        CKB_COBUILD_CHECK2(!has_message, COBUILD_ERROR_SIGHASHALL_DUP);
        SighashAllType s = witness_layout.t->as_SighashAll(&witness_layout);
        *message = s.t->message(&s);
        has_message = true;
      }
    }
    // there are some possibilities:
    // 1. an invalid witness (e.g. empty)
    // 2. WitnessArgs
    // 3. Other cobuild WitnessLayout(e.g. SighashAllOnly)
    // tested by:
    //  tested_by_append_witnessed_less_than_4
    //  tested_by_append_witnessargs
    //  tested_by_append_other_witnesslayout
  }
exit:
  return err;
}

// step 2
static inline int ckb_fetch_otx_start(BytesVecType witnesses, bool *has_otx,
                                      size_t *i, OtxStart *otx_start) {
  int err = COBUILD_ERROR_GENERAL;
  *has_otx = false;
  uint32_t witness_len = witnesses.t->len(&witnesses);
  for (uint32_t index = 0; index < witness_len; index++) {
    WitnessLayoutType witness_layout = {0};
    err = get_witness_layout(witnesses, index, &witness_layout);
    if (err == 0) {
      uint32_t id = witness_layout.t->item_id(&witness_layout);
      if (id == WitnessLayoutOtxStart) {
        // step 4
        // test_cobuild_otx_double_otx_start
        CKB_COBUILD_CHECK2(!*has_otx, COBUILD_ERROR_OTX_START_DUP);
        *has_otx = true;
        *i = index;

        OtxStartType start = witness_layout.t->as_OtxStart(&witness_layout);
        otx_start->start_input_cell = start.t->start_input_cell(&start);
        otx_start->start_output_cell = start.t->start_output_cell(&start);
        otx_start->start_cell_deps = start.t->start_cell_deps(&start);
        otx_start->start_header_deps = start.t->start_header_deps(&start);
      }
    }
  }
  if (has_otx) {
    err = 0;
  }
exit:
  return err;
}
// hash input cell, including CellOutput and cell data
static int hash_input_cell(blake2b_state *ctx, size_t index, size_t *count) {
  // this data source is on stack. When this function returns, all cursors bound
  // to this buffer become invalid.
  uint8_t data_source[DEFAULT_DATA_SOURCE_LENGTH];
  int err = 0;
  // CellOutput
  uint64_t cell_len = MAX_CACHE_SIZE;
  err = ckb_load_cell(MOL2_CACHE_PTR(data_source), &cell_len, 0, index,
                      CKB_SOURCE_INPUT);
  CKB_COBUILD_CHECK(err);
  mol2_cursor_t cell_cursor = {0};
  uint32_t cache_size = (uint32_t)cell_len;
  if (cache_size > MAX_CACHE_SIZE) {
    cache_size = MAX_CACHE_SIZE;
  }
  ckb_new_cursor_with_data(&cell_cursor, cell_len, read_from_cell, data_source,
                           MAX_CACHE_SIZE, index, CKB_SOURCE_INPUT, cache_size);
  ckb_hash_cursor(ctx, cell_cursor);
  (*count) += cell_len;

  // Cell data
  uint64_t cell_data_len = MAX_CACHE_SIZE;
  err = ckb_load_cell_data(MOL2_CACHE_PTR(data_source), &cell_data_len, 0,
                           index, CKB_SOURCE_INPUT);
  CKB_COBUILD_CHECK(err);
  mol2_cursor_t cell_data_cursor = {0};
  cache_size = (uint32_t)cell_data_len;
  if (cache_size > MAX_CACHE_SIZE) {
    cache_size = MAX_CACHE_SIZE;
  }
  ckb_new_cursor_with_data(&cell_data_cursor, cell_data_len,
                           read_from_cell_data, data_source, MAX_CACHE_SIZE,
                           index, CKB_SOURCE_INPUT, cache_size);
  // only hash as uint32_t. 4 bytes is enough
  BLAKE2B_UPDATE(ctx, &cell_data_len, 4);
  (*count) += 4;
  err = ckb_hash_cursor(ctx, cell_data_cursor);
  CKB_COBUILD_CHECK(err);
  (*count) += cell_data_cursor.size;

exit:
  return err;
}

int ckb_generate_smh(const Env *env, mol2_cursor_t message_cursor,
                     uint8_t *smh) {
  bool has_message = message_cursor.size > 0;
  int err = 0;

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
  BLAKE2B_UPDATE(&ctx, env->tx_hash, sizeof(env->tx_hash));
  count += sizeof(env->tx_hash);

  TransactionType tx = env->tx;
  RawTransactionType raw = tx.t->raw(&tx);
  CellInputVecType inputs = raw.t->inputs(&raw);
  uint32_t input_len = inputs.t->len(&inputs);
  BytesVecType witnesses = tx.t->witnesses(&tx);
  uint32_t witness_len = witnesses.t->len(&witnesses);

  // hash input cell and data
  for (uint32_t index = 0; index < input_len; index++) {
    err = hash_input_cell(&ctx, index, &count);
    CKB_COBUILD_CHECK(err);
  }
  // hash remaining witnesses
  for (uint32_t index = input_len; index < witness_len; index++) {
    bool existing = false;
    mol2_cursor_t witness_cursor =
        witnesses.t->get(&witnesses, index, &existing);
    CKB_COBUILD_CHECK2(existing, COBUILD_ERROR_MOL2_UNEXPECTED);
    uint32_t witness_len = witness_cursor.size;
    BLAKE2B_UPDATE(&ctx, &witness_len, 4);
    count += 4;
    err = ckb_hash_cursor(&ctx, witness_cursor);
    count += witness_cursor.size;
    CKB_COBUILD_CHECK(err);
  }
  blake2b_final(&ctx, smh, BLAKE2B_BLOCK_SIZE);
  printf("ckb_generate_smh total hashed %d bytes", count);

exit:
  return err;
}

static int hash_cmp(const void *h1, const void *h2) {
  return memcmp(h1, h2, BLAKE2B_BLOCK_SIZE);
}

static int collect_script_hash(uint8_t *script_hash,
                               uint32_t *script_hash_count, size_t source,
                               size_t field) {
  int err = 0;
  size_t i = 0;
  while (1) {
    uint8_t hash[BLAKE2B_BLOCK_SIZE] = {0};
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    err = ckb_load_cell_by_field(hash, &len, 0, i, source, field);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      err = 0;
      break;
    }
    if (err == CKB_ITEM_MISSING) {
      i += 1;
      continue;
    }
    CKB_COBUILD_CHECK(err);
    CKB_COBUILD_CHECK2(*script_hash_count < MAX_SCRIPT_COUNT,
                       COBUILD_ERROR_GENERAL);
    memcpy(&script_hash[(*script_hash_count) * BLAKE2B_BLOCK_SIZE], hash,
           BLAKE2B_BLOCK_SIZE);
    (*script_hash_count)++;
    i += 1;
  }
exit:
  return err;
}

// For each action in the message, ensure a corresponding type script hash
// (including input/output) matches the action.script_hash. Let A be the set of
// action.script_hash, and B be the set of all input/output script hashes; A ∈ B
// should be satisfied.
static int check_type_script_existing(MessageType msg) {
  int err = 0;
  // cache all type script hashes in input/output cells
  static uint8_t script_hash[BLAKE2B_BLOCK_SIZE * MAX_SCRIPT_COUNT] = {0};
  static uint32_t script_hash_count = 0;
  static bool script_hash_initialized = false;

  if (!script_hash_initialized) {
    err = collect_script_hash(script_hash, &script_hash_count, CKB_SOURCE_INPUT,
                              CKB_CELL_FIELD_TYPE_HASH);
    CKB_COBUILD_CHECK(err);
    err = collect_script_hash(script_hash, &script_hash_count,
                              CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH);
    CKB_COBUILD_CHECK(err);
    err = collect_script_hash(script_hash, &script_hash_count, CKB_SOURCE_INPUT,
                              CKB_CELL_FIELD_LOCK_HASH);
    CKB_COBUILD_CHECK(err);

    // sort for fast searching
    qsort(script_hash, script_hash_count, BLAKE2B_BLOCK_SIZE, hash_cmp);

    script_hash_initialized = true;
  }

  ActionVecType actions = msg.t->actions(&msg);
  uint32_t len = actions.t->len(&actions);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    ActionType action = actions.t->get(&actions, i, &existing);
    CKB_COBUILD_CHECK2(existing, COBUILD_ERROR_GENERAL);
    mol2_cursor_t hash = action.t->script_hash(&action);
    uint8_t hash_buff[BLAKE2B_BLOCK_SIZE] = {0};
    uint32_t len = mol2_read_at(&hash, hash_buff, BLAKE2B_BLOCK_SIZE);
    CKB_COBUILD_CHECK2(len == BLAKE2B_BLOCK_SIZE, COBUILD_ERROR_MESSAGE);
    void *found = bsearch(hash_buff, script_hash, script_hash_count,
                          BLAKE2B_BLOCK_SIZE, hash_cmp);
    // test_cobuild_otx_noexistent_type_script_hash
    CKB_COBUILD_CHECK2(found != NULL, COBUILD_ERROR_TYPESCRIPT_MISSING);
  }

exit:
  return err;
}

// Parse the `original_seal` and return underlying seal after adjustment. The
// first byte of `seal` is considered as an id of message calculation flow.
static int parse_seal(const mol2_cursor_t original_seal, mol2_cursor_t *seal,
                      uint8_t *message_calculation_flow) {
  int err = 0;
  uint32_t prefix_length = 1;
  uint8_t prefix[1] = {0};

  uint32_t len = mol2_read_at(&original_seal, prefix, prefix_length);
  CKB_COBUILD_CHECK2(len == prefix_length, COBUILD_ERROR_SEAL);
  *message_calculation_flow = prefix[0];
  *seal = mol2_cursor_slice_start(&original_seal, prefix_length);

exit:
  return err;
}

int ckb_cobuild_normal_entry(const Env *env, ScriptEntryType callback) {
  TransactionType tx = env->tx;
  BytesVecType witnesses = tx.t->witnesses(&tx);

  int err = COBUILD_ERROR_GENERAL;
  uint8_t smh[BLAKE2B_BLOCK_SIZE];
  mol2_cursor_t seal = {0};

  MessageType message = {0};
  // step 8.a, 8.b
  err = ckb_fetch_sighash_message(witnesses, &message);
  CKB_COBUILD_CHECK(err);
  bool has_message = message.cur.size > 0;
  if (has_message) {
    print_cursor("message", message.cur);
    // step 8.c
    err = check_type_script_existing(message);
    CKB_COBUILD_CHECK(err);
  }

  uint8_t seal_source[DEFAULT_DATA_SOURCE_LENGTH];
  mol2_cursor_t original_seal = {0};
  {
    // step 8.d
    // step 8.f
    mol2_cursor_t witness = {0};
    err = ckb_new_witness_cursor(&witness, seal_source, MAX_CACHE_SIZE, 0,
                                 CKB_SOURCE_GROUP_INPUT);
    CKB_COBUILD_CHECK(err);
    WitnessLayoutType witness_layout = make_WitnessLayout(&witness);
    CKB_COBUILD_CHECK2(!verify_WitnessLayout(&witness_layout),
                       COBUILD_ERROR_SIGHASHALL_NOSEAL);

    uint32_t id = witness_layout.t->item_id(&witness_layout);
    switch (id) {
      case WitnessLayoutSighashAll: {
        SighashAllType s = witness_layout.t->as_SighashAll(&witness_layout);
        original_seal = s.t->seal(&s);
      } break;
      case WitnessLayoutSighashAllOnly: {
        SighashAllOnlyType o =
            witness_layout.t->as_SighashAllOnly(&witness_layout);
        original_seal = o.t->seal(&o);
      } break;
      default: {
        // the union id should be SighashAll or SighashAllOnly. otherwise, it
        // fails and mark it as non cobuild. tested by test_wrong_union_id
        printf("error in fetch_seal, id = %u", id);
        CKB_COBUILD_CHECK2(false, COBUILD_ERROR_SIGHASHALL_NOSEAL);
      } break;
    }
  }
  print_cursor("seal", original_seal);

  // step 8.e
  err = ckb_check_others_in_group();
  // tested by test_non_empty_witness
  CKB_COBUILD_CHECK(err);

  // support more message calculation flows base on the first byte of seal
  uint8_t message_calculation_flow = 0;
  err = parse_seal(original_seal, &seal, &message_calculation_flow);
  CKB_COBUILD_CHECK(err);

  if (message_calculation_flow == MessageCalculationFlowBlake2b) {
    // step 8.g
    err = ckb_generate_smh(env, message.cur, smh);
    CKB_COBUILD_CHECK(err);
    print_raw_data("smh", smh, BLAKE2B_BLOCK_SIZE);
  } else {
    // we can add more message calculation flows in the further, based on the
    // first byte of seal
    CKB_COBUILD_CHECK2(false, COBUILD_ERROR_FLOW);
  }
  err = callback(env, smh, seal);
  if (err) {
    printf("callback failed: %d", err);
    // terminated immediately
    ckb_exit(err);
  }
exit:
  return err;
}

int ckb_generate_otx_smh(const Env *env, mol2_cursor_t message_cursor,
                         uint8_t *smh, const OtxStart *start, const Otx *size) {
  int err = 0;
  blake2b_state ctx;
  size_t count = 0;
  new_otx_blake2b(&ctx);
  printf(
      "start_input_cell = %d, start_output_cell = %d, start_cell_deps = %d, "
      "start_header_deps = %d",
      start->start_input_cell, start->start_output_cell, start->start_cell_deps,
      start->start_header_deps);
  printf(
      "input_cells = %d, output_cells = %d, cell_deps = %d, header_deps = %d",
      size->input_cells, size->output_cells, size->cell_deps,
      size->header_deps);

  err = ckb_hash_cursor(&ctx, message_cursor);
  CKB_COBUILD_CHECK(err);
  count += message_cursor.size;

  BLAKE2B_UPDATE(&ctx, &size->input_cells, 4);
  count += 4;

  TransactionType tx = env->tx;
  RawTransactionType raw = tx.t->raw(&tx);
  CellInputVecType inputs = raw.t->inputs(&raw);

  // hash input cell and data
  CKB_COBUILD_CHECK2(
      start->start_input_cell + size->input_cells >= start->start_input_cell,
      COBUILD_ERROR_OVERFLOW);
  for (size_t index = start->start_input_cell;
       index < (start->start_input_cell + size->input_cells); index++) {
    // CellInput
    bool existing = false;
    CellInputType input = inputs.t->get(&inputs, index, &existing);
    CKB_COBUILD_CHECK2(existing, COBUILD_ERROR_MOL2_UNEXPECTED);
    err = ckb_hash_cursor(&ctx, input.cur);
    CKB_COBUILD_CHECK(err);
    count += input.cur.size;

    err = hash_input_cell(&ctx, index, &count);
    CKB_COBUILD_CHECK(err);
  }
  // hash output cell and data
  CKB_COBUILD_CHECK2(
      start->start_output_cell + size->output_cells >= start->start_output_cell,
      COBUILD_ERROR_OVERFLOW);
  BLAKE2B_UPDATE(&ctx, &size->output_cells, 4);
  count += 4;
  CellOutputVecType outputs = raw.t->outputs(&raw);
  BytesVecType outputs_data = raw.t->outputs_data(&raw);
  for (size_t index = start->start_output_cell;
       index < (start->start_output_cell + size->output_cells); index++) {
    bool existing = false;
    CellOutputType output = outputs.t->get(&outputs, index, &existing);
    CKB_COBUILD_CHECK2(existing, COBUILD_ERROR_MOL2_UNEXPECTED);
    err = ckb_hash_cursor(&ctx, output.cur);
    CKB_COBUILD_CHECK(err);
    count += output.cur.size;

    existing = false;
    mol2_cursor_t output_data_cursor =
        outputs_data.t->get(&outputs_data, index, &existing);
    CKB_COBUILD_CHECK2(existing, COBUILD_ERROR_MOL2_UNEXPECTED);
    uint32_t data_len = output_data_cursor.size;
    BLAKE2B_UPDATE(&ctx, &data_len, 4);
    count += 4;
    err = ckb_hash_cursor(&ctx, output_data_cursor);
    CKB_COBUILD_CHECK(err);
    count += output_data_cursor.size;
  }

  // hash cell deps
  CKB_COBUILD_CHECK2(
      start->start_cell_deps + size->cell_deps >= start->start_cell_deps,
      COBUILD_ERROR_OVERFLOW);
  BLAKE2B_UPDATE(&ctx, &size->cell_deps, 4);
  count += 4;
  CellDepVecType cell_deps = raw.t->cell_deps(&raw);
  for (size_t index = start->start_cell_deps;
       index < (start->start_cell_deps + size->cell_deps); index++) {
    bool existing = false;
    CellDepType cell_dep = cell_deps.t->get(&cell_deps, index, &existing);
    CKB_COBUILD_CHECK2(existing, COBUILD_ERROR_MOL2_UNEXPECTED);
    err = ckb_hash_cursor(&ctx, cell_dep.cur);
    count += cell_dep.cur.size;
  }

  // hash header deps
  CKB_COBUILD_CHECK2(
      start->start_header_deps + size->header_deps >= start->start_header_deps,
      COBUILD_ERROR_OVERFLOW);
  BLAKE2B_UPDATE(&ctx, &size->header_deps, 4);
  count += 4;
  Byte32VecType header_deps = raw.t->header_deps(&raw);
  for (size_t index = start->start_header_deps;
       index < (start->start_header_deps + size->header_deps); index++) {
    bool existing = false;
    mol2_cursor_t header_dep_cursor =
        header_deps.t->get(&header_deps, index, &existing);
    CKB_COBUILD_CHECK2(existing, COBUILD_ERROR_MOL2_UNEXPECTED);
    err = ckb_hash_cursor(&ctx, header_dep_cursor);
    count += header_dep_cursor.size;
  }
  printf("ckb_generate_otx_smh totally hashed %d bytes", count);
  blake2b_final(&ctx, smh, BLAKE2B_BLOCK_SIZE);
exit:
  return err;
}

int ckb_cobuild_entry(const Env *env, ScriptEntryType callback,
                      bool *cobuild_enabled) {
  int err = 0;
  size_t execution_count = 0;
  uint8_t smh[BLAKE2B_BLOCK_SIZE] = {0};
  mol2_cursor_t original_seal = {0};
  mol2_cursor_t seal = {0};

  TransactionType tx = env->tx;
  BytesVecType witnesses = tx.t->witnesses(&tx);
  uint32_t witness_len = witnesses.t->len(&witnesses);

  // Legacy Flow Handling
  *cobuild_enabled = false;
  for (uint32_t i = 0; i < witness_len; i++) {
    if (get_witness_layout(witnesses, i, NULL) == 0) {
      *cobuild_enabled = true;
      break;
    }
  }
  if (!*cobuild_enabled) {
    goto exit;
  }

  // step 1
  uint32_t is = 0, ie = 0, os = 0, oe = 0, cs = 0, ce = 0, hs = 0, he = 0;
  size_t i = 0;
  bool has_otx = false;
  OtxStart otx_start = {0};
  // step 2
  // step 4
  err = ckb_fetch_otx_start(witnesses, &has_otx, &i, &otx_start);
  CKB_COBUILD_CHECK(err);
  if (!has_otx) {
    // step 3
    printf("No otx detected");
    return ckb_cobuild_normal_entry(env, callback);
  }
  // step 5
  is = otx_start.start_input_cell;
  ie = is;
  os = otx_start.start_output_cell;
  oe = os;
  cs = otx_start.start_cell_deps;
  ce = cs;
  hs = otx_start.start_header_deps;
  he = hs;
  printf("ie = %d, oe = %d, ce = %d, he = %d", ie, oe, ce, he);
  uint32_t index = i + 1;
  printf("Otx starts at index %d(inclusive)", index);
  for (; index < witness_len; index++) {
    WitnessLayoutType witness_layout = {0};
    err = get_witness_layout(witnesses, index, &witness_layout);
    if (err != 0) {
      // step 6, not WitnessLayoutOtx
      break;
    }
    uint32_t id = witness_layout.t->item_id(&witness_layout);
    if (id != WitnessLayoutOtx) {
      // step 6
      // test_cobuild_otx_noexistent_otx_id && err == 0
      break;
    }
    OtxType otx = witness_layout.t->as_Otx(&witness_layout);
    MessageType message = otx.t->message(&otx);
    Otx size = {
        .input_cells = otx.t->input_cells(&otx),
        .output_cells = otx.t->output_cells(&otx),
        .cell_deps = otx.t->cell_deps(&otx),
        .header_deps = otx.t->header_deps(&otx),
    };
    // 6.b
    if (size.input_cells == 0 && size.output_cells == 0 &&
        size.cell_deps == 0 && size.header_deps == 0) {
      // test_cobuild_otx_msg_size_all_0
      CKB_COBUILD_CHECK2(false, COBUILD_ERROR_WRONG_OTX);
    }
    // step 6.c
    err = check_type_script_existing(message);
    CKB_COBUILD_CHECK(err);
    // step 6.d
    bool found = false;
    size_t end = (size_t)(ie + otx.t->input_cells(&otx));
    for (size_t index2 = ie; index2 < end; index2++) {
      uint8_t hash[BLAKE2B_BLOCK_SIZE];
      uint64_t len = BLAKE2B_BLOCK_SIZE;
      err = ckb_load_cell_by_field(hash, &len, 0, index2, CKB_SOURCE_INPUT,
                                   CKB_CELL_FIELD_LOCK_HASH);
      CKB_COBUILD_CHECK(err);
      if (memcmp(hash, env->current_script_hash, sizeof(hash)) == 0) {
        found = true;
        break;
      }
    }
    if (!found) {
      ie += otx.t->input_cells(&otx);
      oe += otx.t->output_cells(&otx);
      ce += otx.t->cell_deps(&otx);
      he += otx.t->header_deps(&otx);
      continue;
    }
    // step 6.e
    OtxStart start = {
        .start_input_cell = ie,
        .start_output_cell = oe,
        .start_cell_deps = ce,
        .start_header_deps = he,
    };
    err = ckb_generate_otx_smh(env, message.cur, smh, &start, &size);
    CKB_COBUILD_CHECK(err);
    print_raw_data("smh", smh, BLAKE2B_BLOCK_SIZE);
    // step 6.f
    bool seal_found = false;
    SealPairVecType seals = otx.t->seals(&otx);
    uint32_t seal_len = seals.t->len(&seals);
    for (uint32_t seal_index = 0; seal_index < seal_len; seal_index++) {
      bool existing = false;
      uint8_t hash[BLAKE2B_BLOCK_SIZE];
      SealPairType loop_seal = seals.t->get(&seals, seal_index, &existing);
      CKB_COBUILD_CHECK2(existing, COBUILD_ERROR_GENERAL);
      mol2_cursor_t script_hash = loop_seal.t->script_hash(&loop_seal);
      size_t len = mol2_read_at(&script_hash, hash, sizeof(hash));
      CKB_COBUILD_CHECK2(len == sizeof(hash), COBUILD_ERROR_GENERAL);
      if (memcmp(hash, env->current_script_hash, sizeof(hash)) == 0) {
        // step 6.g
        original_seal = loop_seal.t->seal(&loop_seal);
        print_cursor("seal", original_seal);
        // duplicated seals are ignored
        seal_found = true;
        break;
      }
    }
    // test_cobuild_otx_no_seal
    CKB_COBUILD_CHECK2(seal_found, COBUILD_ERROR_SEAL);
    // support more message calculation flows base on the first byte of seal
    uint8_t message_calculation_flow = 0;
    err = parse_seal(original_seal, &seal, &message_calculation_flow);
    CKB_COBUILD_CHECK(err);
    if (message_calculation_flow == MessageCalculationFlowBlake2b) {
      execution_count++;
      err = callback(env, smh, seal);
      if (err) {
        printf("callback failed: %d", err);
        // terminated immediately
        ckb_exit(err);
      }
    } else {
      // test_cobuild_otx_msg_flow
      CKB_COBUILD_CHECK2(false, COBUILD_ERROR_FLOW);
    }
    // step 6.h
    ie += otx.t->input_cells(&otx);
    oe += otx.t->output_cells(&otx);
    ce += otx.t->cell_deps(&otx);
    he += otx.t->header_deps(&otx);
  }  // end of step 6 loop
  printf("Otx ends at index %d(exclusive)", index);

  // step 7
  size_t j = index;
  for (uint32_t index = 0; index < witness_len; index++) {
    // [0, i) [j, +infinity)
    if (index < i || index >= j) {
      WitnessLayoutType witness_layout = {0};
      err = get_witness_layout(witnesses, index, &witness_layout);
      if (err == 0) {
        // test_cobuild_otx_noexistent_otx_id
        uint32_t id = witness_layout.t->item_id(&witness_layout);
        CKB_COBUILD_CHECK2(id != WitnessLayoutOtx, COBUILD_ERROR_WRONG_OTX);
      }
    }
  }

  // step 8
  bool found = false;
  for (size_t index = 0;; index++) {
    // scan all input cell in [0, is) and [ie, +infinity)
    // if is == ie, it is always true
    if (index < is || index >= ie) {
      uint8_t hash[BLAKE2B_BLOCK_SIZE];
      uint64_t len = BLAKE2B_BLOCK_SIZE;
      err = ckb_load_cell_by_field(hash, &len, 0, index, CKB_SOURCE_INPUT,
                                   CKB_CELL_FIELD_LOCK_HASH);
      CKB_COBUILD_CHECK_LOOP(err);
      if (memcmp(hash, env->current_script_hash, sizeof(hash)) == 0) {
        printf(
            "Same lock script found beyond otx, at index %d. "
            "ckb_cobuild_normal_entry called.",
            index);
        found = true;
        break;
      }
    }
  }
  if (found) {
    printf("extra callback is invoked");
    execution_count++;
    err = ckb_cobuild_normal_entry(env, callback);
    CKB_COBUILD_CHECK(err);
  }
  CKB_COBUILD_CHECK2(execution_count > 0, COBUILD_ERROR_NO_CALLBACK);
  printf("execution_count = %d", execution_count);
exit:
  return err;
}

#endif  // __COBUILD_H__
