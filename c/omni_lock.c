// clang-format off
#include <stdio.h>
#include <blake2b.h>

// it's used by blockchain-api2.h, the behavior when panic
#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);
#define MOLECULEC_VERSION 7000
#include "blockchain-api2.h"
#include "ckb_consts.h"

#if defined(CKB_USE_SIM)
// exclude ckb_dlfcn.h
#define CKB_C_STDLIB_CKB_DLFCN_H_
#include "ckb_syscall_omni_lock_sim.h"
#else
#include "ckb_syscalls.h"
#endif
#include "secp256k1_helper.h"
// CHECK is defined in secp256k1
#undef CHECK
#include "ckb_swappable_signatures.h"
#include "ckb_identity.h"
#include "ckb_smt.h"

#include "rce.h"
#include "omni_lock_mol2.h"
#include "molecule2_verify.h"

#include "omni_lock_acp.h"
#include "omni_lock_time_lock.h"
#include "omni_lock_supply.h"
#include "cobuild.h"
// clang-format on

#define SCRIPT_SIZE 32768
#define MAX_LOCK_SCRIPT_HASH_COUNT 2048
#define MAX_SIGNATURE_SIZE 1024
#define OMNI_ROOT_MASK 1
#define ACP_MASK (1 << 1)
#define SINCE_MASK (1 << 2)
#define SUPPLY_MASK (1 << 3)

#define MAX_CODE_SIZE (1024 * 400)

enum OmniLockErrorCode {
  // omni lock error code is starting from 80
  ERROR_UNKNOWN_FLAGS = 80,
  ERROR_PROOF_LENGTH_MISMATCHED,
  ERROR_NO_OMNIRULE,
  ERROR_NO_WHITE_LIST,
  ERROR_INVALID_IDENTITY_ID,
  ERROR_INVALID_OMNI_LOCK_ARGS,
  ERROR_ISO9796_2_VERIFY,
  ERROR_ARGS_FORMAT,
};

// parsed from args in lock script
typedef struct ArgsType {
  CkbIdentityType id;

  uint8_t omni_lock_flags;

  bool has_omni_root;
  uint8_t omni_root[32];

  bool has_since;
  uint64_t since;

  bool has_acp;
  uint8_t ckb_minimum;  // Used for ACP
  uint8_t udt_minimum;  // used for ACP

  bool has_supply;
  uint8_t info_cell[32];  // type script hash
} ArgsType;

// parsed from lock in witness or seal
typedef struct WitnessLockType {
  bool has_identity;
  bool has_signature;
  bool has_proofs;

  CkbIdentityType id;
  uint32_t signature_size;
  uint8_t signature[MAX_SIGNATURE_SIZE];
  uint32_t preimage_size;
  uint8_t preimage[MAX_PREIMAGE_SIZE];

  SmtProofEntryVecType proofs;
} WitnessLockType;

uint8_t g_code_buff[MAX_CODE_SIZE] __attribute__((aligned(RISCV_PGSIZE)));

// make compiler happy
int make_cursor_from_witness(WitnessArgsType *witness, bool *_input) {
  return -1;
}

//
// move cur by offset within seg.
// return NULL if out of bounds.
uint8_t *safe_move_to(mol_seg_t seg, uint8_t *cur, uint32_t offset) {
  uint8_t *end = seg.ptr + seg.size;

  if (cur < seg.ptr || cur >= end) {
    return NULL;
  }
  uint8_t *next = cur + offset;
  if (next < seg.ptr || next >= end) {
    return NULL;
  }
  return next;
}

bool is_memory_enough(mol_seg_t seg, const uint8_t *cur, uint32_t len) {
  uint8_t *end = seg.ptr + seg.size;

  if (cur < seg.ptr || cur >= end) {
    return false;
  }
  const uint8_t *next = cur + len;
  // == end is allowed
  if (next < seg.ptr || next > end) {
    return false;
  }
  return true;
}

// memory layout of args:
// <identity, 21 bytes> <omni_lock args>
// <omni_lock flags, 1 byte>  <OMNI cell type id, 32 bytes, optional> <ckb/udt
// min, 2 bytes, optional> <since, 8 bytes, optional>
int parse_args(ScriptType script, ArgsType *args) {
  int err = 0;

  // TODO: do we need to validate Script structure here?
  mol2_cursor_t script_args = script.t->args(&script);

  // parse flags
  CHECK2(script_args.size >= 1, ERROR_ARGS_FORMAT);
  CHECK2(mol2_read_at(&script_args, &args->id.flags, 1) == 1,
         ERROR_ARGS_FORMAT);
  script_args = mol2_cursor_slice_start(&script_args, 1);

  // parse blake160
  CHECK2(script_args.size >= 20, ERROR_ARGS_FORMAT);
  CHECK2(mol2_read_at(&script_args, args->id.id, 20) == 20, ERROR_ARGS_FORMAT);
  script_args = mol2_cursor_slice_start(&script_args, 20);

  CHECK2(script_args.size >= 1, ERROR_ARGS_FORMAT);
  CHECK2(mol2_read_at(&script_args, &args->omni_lock_flags, 1) == 1,
         ERROR_ARGS_FORMAT);
  script_args = mol2_cursor_slice_start(&script_args, 1);

  args->has_omni_root = args->omni_lock_flags & OMNI_ROOT_MASK;
  args->has_acp = args->omni_lock_flags & ACP_MASK;
  args->has_since = args->omni_lock_flags & SINCE_MASK;
  args->has_supply = args->omni_lock_flags & SUPPLY_MASK;
  uint32_t expected_size = 0;
  if (args->has_omni_root) {
    expected_size += 32;
  }
  if (args->has_acp) {
    expected_size += 2;
  }
  if (args->has_since) {
    expected_size += 8;
  }
  if (args->has_supply) {
    expected_size += 32;
  }

  CHECK2(script_args.size == expected_size, ERROR_ARGS_FORMAT);
  if (expected_size > 0) {
    if (args->has_omni_root) {
      CHECK2(mol2_read_at(&script_args, args->omni_root, 32) == 32,
             ERROR_ARGS_FORMAT);
      script_args = mol2_cursor_slice_start(&script_args, 32);
    }
    if (args->has_acp) {
      CHECK2(mol2_read_at(&script_args, &args->ckb_minimum, 1) == 1,
             ERROR_ARGS_FORMAT);
      script_args = mol2_cursor_slice_start(&script_args, 1);
      CHECK2(mol2_read_at(&script_args, &args->udt_minimum, 1) == 1,
             ERROR_ARGS_FORMAT);
      script_args = mol2_cursor_slice_start(&script_args, 1);
    }
    if (args->has_since) {
      CHECK2(mol2_read_at(&script_args, (uint8_t *)(&args->since), 8) == 8,
             ERROR_ARGS_FORMAT);
      script_args = mol2_cursor_slice_start(&script_args, 8);
    }
    if (args->has_supply) {
      CHECK2(mol2_read_at(&script_args, args->info_cell, 32) == 32,
             ERROR_ARGS_FORMAT);
      script_args = mol2_cursor_slice_start(&script_args, 32);
    }
    CHECK2(script_args.size == 0, ERROR_INVALID_MOL_FORMAT);
  }

exit:
  return err;
}

int smt_verify_identity(CkbIdentityType *id, SmtProofEntryVecType *proofs,
                        RceState *rce_state) {
  int err = 0;
  uint32_t proof_len = proofs->t->len(proofs);
  CHECK2(proof_len == rce_state->rcrules_count, ERROR_PROOF_LENGTH_MISMATCHED);

  uint8_t key[SMT_KEY_BYTES] = {0};
  key[0] = id->flags;
  memcpy(key + 1, id->id, BLAKE160_SIZE);

  smt_pair_t entries[1];
  smt_state_t states;
  smt_state_init(&states, entries, 1);
  smt_state_insert(&states, key, SMT_VALUE_EMPTY);

  uint8_t proof_mask = 0x3;  // both
  for (uint32_t i = 0; i < proof_len; i++) {
    bool existing = false;
    SmtProofEntryType proof_entry = proofs->t->get(proofs, i, &existing);
    CHECK2(existing, ERROR_INVALID_MOL_FORMAT);
    mol2_cursor_t proof = proof_entry.t->proof(&proof_entry);

    const RCRule *current_rule = &rce_state->rcrules[i];
    err = rce_verify_one_rule(rce_state, &states, NULL, NULL, proof_mask, proof,
                              current_rule);
    CHECK(err);
  }
  if (rce_state->has_wl) {
    if (rce_state->both_on_wl) {
      err = 0;
    } else {
      err = ERROR_NOT_ON_WHITE_LIST;
    }
  } else {
    // all black list, it's not allowed
    err = ERROR_NO_WHITE_LIST;
  }
exit:
  return err;
}

static int parse_witness_lock(WitnessLockType *witness_lock,
                              mol2_cursor_t *seal) {
  int err = 0;
  witness_lock->has_signature = false;
  witness_lock->has_identity = false;
  witness_lock->has_proofs = false;
  // convert Bytes to OmniLockWitnessLock
  OmniLockWitnessLockType mol_witness_lock = make_OmniLockWitnessLock(seal);
  IdentityOptType identity_opt =
      mol_witness_lock.t->omni_identity(&mol_witness_lock);
  witness_lock->has_identity = identity_opt.t->is_some(&identity_opt);
  if (witness_lock->has_identity) {
    IdentityType omni_identity = identity_opt.t->unwrap(&identity_opt);
    mol2_cursor_t id_cur = omni_identity.t->identity(&omni_identity);

    uint8_t buff[CKB_IDENTITY_LEN] = {0};
    uint32_t read_len = mol2_read_at(&id_cur, buff, sizeof(buff));
    CHECK2(read_len == CKB_IDENTITY_LEN, ERROR_INVALID_MOL_FORMAT);
    witness_lock->id.flags = buff[0];
    memcpy(witness_lock->id.id, buff + 1, CKB_IDENTITY_LEN - 1);

    witness_lock->proofs = omni_identity.t->proofs(&omni_identity);
    witness_lock->has_proofs = true;
  }

  BytesOptType signature_opt = mol_witness_lock.t->signature(&mol_witness_lock);
  witness_lock->has_signature = signature_opt.t->is_some(&signature_opt);
  if (witness_lock->has_signature) {
    mol2_cursor_t signature_cursor = signature_opt.t->unwrap(&signature_opt);
    witness_lock->signature_size = mol2_read_at(
        &signature_cursor, witness_lock->signature, signature_cursor.size);
    CHECK2(signature_cursor.size == witness_lock->signature_size,
           ERROR_INVALID_MOL_FORMAT);
  }
  BytesOptType preimage_opt = mol_witness_lock.t->preimage(&mol_witness_lock);
  if (preimage_opt.t->is_some(&preimage_opt)) {
    mol2_cursor_t preimage_cursor = preimage_opt.t->unwrap(&preimage_opt);
    witness_lock->preimage_size = mol2_read_at(
        &preimage_cursor, witness_lock->preimage, preimage_cursor.size);
    CHECK2(preimage_cursor.size == witness_lock->preimage_size,
           ERROR_INVALID_MOL_FORMAT);
  } else {
    witness_lock->preimage_size = 0;
  }

exit:
  return err;
}

// smh is short for signing message hash
int omnilock_entry(const Env *env, const uint8_t *smh, mol2_cursor_t seal) {
  int err = 0;
  WitnessLockType witness_lock = {0};

  // this identity can be either from witness lock (witness_lock.id) or script
  // args (args.id)
  CkbIdentityType identity = {0};
  // In some scenarios(e.g. owner lock), corresponding witness doesn't exist
  if (seal.size > 0) {
    err = parse_witness_lock(&witness_lock, &seal);
    CHECK(err);
  }

  const ArgsType *args = (const ArgsType *)env->script_specific_data;

  if (args->has_omni_root) {
    if (witness_lock.has_identity) {
      identity = witness_lock.id;
    } else {
      identity = args->id;
    }
  } else {
    identity = args->id;
  }

  // regulation compliance, also as administrators
  if (witness_lock.has_identity) {
    CHECK2(args->has_omni_root, ERROR_INVALID_MOL_FORMAT);
    CHECK2(witness_lock.has_proofs, ERROR_INVALID_MOL_FORMAT);

    RceState rce_state;
    rce_init_state(&rce_state);
    rce_state.rcrules_in_input_cell = true;
    err = rce_gather_rcrules_recursively(&rce_state, args->omni_root, 0);
    CHECK(err);
    CHECK2(rce_state.rcrules_count > 0, ERROR_NO_OMNIRULE);
    CHECK2(rce_state.has_wl, ERROR_NO_WHITE_LIST);

    // verify blake160 against proof, using omni rules
    err = smt_verify_identity(&identity, &witness_lock.proofs, &rce_state);
    CHECK(err);
  } else {
    // time lock is not used for administrators
    if (args->has_since) {
      err = check_since(args->since);
      CHECK(err);
    }
    if (args->has_supply) {
      err = check_supply(args->info_cell);
      CHECK(err);
    }
    // ACP without signature is not used for administrators
    if (args->has_acp && !witness_lock.has_signature) {
      uint64_t min_ckb_amount = 0;
      uint128_t min_udt_amount = 0;
      process_amount(args->ckb_minimum, args->udt_minimum, &min_ckb_amount,
                     &min_udt_amount);
      // skip checking identity to follow ACP
      return check_payment_unlock(min_ckb_amount, min_udt_amount);
    }
  }
  ckb_identity_init_code_buffer(g_code_buff, MAX_CODE_SIZE);
  err = ckb_verify_identity(&identity, witness_lock.signature,
                            witness_lock.signature_size, witness_lock.preimage,
                            witness_lock.preimage_size, smh);
  CHECK(err);
exit:
  return err;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main() {
#endif
  int err = 0;
  Env env;
  err = ckb_env_initialize(&env);
  CHECK(err);
  ArgsType args = {0};
  err = parse_args(env.current_script, &args);
  CHECK(err);
  env.script_specific_data = &args;

  bool cobuild_activated = false;
  err = ckb_cobuild_entry(&env, omnilock_entry, &cobuild_activated);
  CHECK(err);
  printf("cobuild_activated = %d", cobuild_activated);
  if (!cobuild_activated) {
    uint8_t witness_source[DEFAULT_DATA_SOURCE_LENGTH];
    mol2_cursor_t lock = {0};
    {
      mol2_cursor_t witness_cursor;
      err = ckb_new_witness_cursor(&witness_cursor, witness_source,
                                   MAX_CACHE_SIZE, 0, CKB_SOURCE_GROUP_INPUT);
      // when witness is missing, empty or not accessible, make it zero length.
      // don't fail, because owner lock without omni doesn't require witness.
      // when it's zero length, any further actions on witness will fail.
      if (err == 0) {
        if (witness_cursor.size > 0) {
          WitnessArgsType witness_args = make_WitnessArgs(&witness_cursor);
          CHECK2(!verify_WitnessArgs(&witness_args),
                 ERROR_INVALID_WITNESS_FORMAT);

          BytesOptType lock_opt = witness_args.t->lock(&witness_args);
          if (lock_opt.t->is_some(&lock_opt)) {
            lock = lock_opt.t->unwrap(&lock_opt);
          }
        }
      }
    }

    uint8_t smh[BLAKE2B_BLOCK_SIZE] = {0};
    if (lock.size > 0) {
      err = generate_sighash_all(smh, BLAKE2B_BLOCK_SIZE);
      CHECK(err);
    }
    err = omnilock_entry(&env, smh, lock);
    CHECK(err);
  }
exit:
  return err;
}
