#ifndef __MOLECULE2_VERIFY_H__
#define __MOLECULE2_VERIFY_H__

#include "cobuild_basic_mol2.h"
#include "cobuild_top_level_mol2.h"
#include "molecule2_reader.h"

#ifndef BLAKE2B_BLOCK_SIZE
#define BLAKE2B_BLOCK_SIZE 32
#endif  // BLAKE2B_BLOCK_SIZE

typedef enum WitnessLayoutId {
  WitnessLayoutSighashAll = 4278190081,
  WitnessLayoutSighashAllOnly = 4278190082,
  WitnessLayoutOtx = 4278190083,
  WitnessLayoutOtxStart = 4278190084,
} WitnessLayoutId;

int verify_WitnessArgs(WitnessArgsType *witness);
int verify_WitnessLayout(WitnessLayoutType *witness);

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// If it is get by other struct, not need to verify
int verify_Bytes(mol2_cursor_t cur) { return mol2_fixvec_verify(&cur, 1); }

int verify_BytesOpt(mol2_cursor_t cur) {
  int err = MOL2_OK;
  BytesOptType bytes_opt = make_BytesOpt(&cur);

  if (bytes_opt.t->is_some(&bytes_opt)) {
    CHECK(verify_Bytes(bytes_opt.cur));
  }
exit:
  return err;
}

int verify_WitnessArgs(WitnessArgsType *witness) {
  int err = MOL2_OK;

  BytesOptType lock = witness->t->lock(witness);
  CHECK(verify_BytesOpt(lock.cur));
  BytesOptType input_type = witness->t->input_type(witness);
  CHECK(verify_BytesOpt(input_type.cur));
  BytesOptType output_type = witness->t->output_type(witness);
  CHECK(verify_BytesOpt(output_type.cur));

exit:
  return err;
}

int verify_Action(ActionType *action) {
  int err = MOL2_OK;
  mol2_cursor_t data = mol2_table_slice_by_index(&action->cur, 2);
  CHECK(verify_Bytes(data));

  mol2_cursor_t script_hash = action->t->script_hash(action);
  CHECK(mol2_verify_fixed_size(&script_hash, BLAKE2B_BLOCK_SIZE));

  mol2_cursor_t script_info_hash = action->t->script_info_hash(action);
  CHECK(mol2_verify_fixed_size(&script_info_hash, BLAKE2B_BLOCK_SIZE));

exit:
  return err;
}

int verify_ActionVec(ActionVecType *actions) {
  int err = MOL2_OK;

  uint32_t len = actions->t->len(actions);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    ActionType action = actions->t->get(actions, i, &existing);
    CHECK2(existing, MOL2_ERR_INDEX_OUT_OF_BOUNDS);
    CHECK(verify_Action(&action));
  }

exit:
  return err;
}

int verify_Message(MessageType *message) {
  int err = MOL2_OK;
  ActionVecType actions = message->t->actions(message);
  CHECK(verify_ActionVec(&actions));

exit:
  return err;
}

int verify_SealPair(SealPairType *seal_pair) {
  int err = MOL2_OK;
  mol2_cursor_t script_hash = seal_pair->t->script_hash(seal_pair);
  CHECK(mol2_verify_fixed_size(&script_hash, BLAKE2B_BLOCK_SIZE));

  mol2_cursor_t seal = mol2_table_slice_by_index(&seal_pair->cur, 1);
  CHECK(verify_Bytes(seal));

exit:
  return err;
}

int verify_SealPairVec(SealPairVecType *seals) {
  int err = MOL2_OK;
  uint32_t len = seals->t->len(seals);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    SealPairType seal_pair = seals->t->get(seals, i, &existing);
    CHECK2(existing, MOL2_ERR_INDEX_OUT_OF_BOUNDS);
    CHECK(verify_SealPair(&seal_pair));
  }

exit:
  return err;
}

int verify_SighashAll(SighashAllType *sighash_all) {
  int err = MOL2_OK;
  MessageType message = sighash_all->t->message(sighash_all);
  CHECK(verify_Message(&message));

  mol2_cursor_t seal = mol2_table_slice_by_index(&sighash_all->cur, 1);
  CHECK(verify_Bytes(seal));

exit:
  return err;
}

int verify_SighashAllOnly(SighashAllOnlyType *signhash_all_only) {
  int err = MOL2_OK;
  mol2_cursor_t seal = mol2_table_slice_by_index(&signhash_all_only->cur, 0);
  CHECK(verify_Bytes(seal));

exit:
  return err;
}

int verify_Otx(OtxType *otx) {
  int err = MOL2_OK;
  mol2_cursor_t input_cells = mol2_table_slice_by_index(&otx->cur, 0);
  CHECK(mol2_verify_fixed_size(&input_cells, MOL2_NUM_T_SIZE));
  mol2_cursor_t output_cells = mol2_table_slice_by_index(&otx->cur, 1);
  CHECK(mol2_verify_fixed_size(&output_cells, MOL2_NUM_T_SIZE));
  mol2_cursor_t cell_deps = mol2_table_slice_by_index(&otx->cur, 2);
  CHECK(mol2_verify_fixed_size(&cell_deps, MOL2_NUM_T_SIZE));
  mol2_cursor_t header_deps = mol2_table_slice_by_index(&otx->cur, 3);
  CHECK(mol2_verify_fixed_size(&header_deps, MOL2_NUM_T_SIZE));
  MessageType message = Otx_get_message_impl(otx);
  CHECK(verify_Message(&message));
  SealPairVecType seals = Otx_get_seals_impl(otx);
  CHECK(verify_SealPairVec(&seals));

exit:
  return err;
}

int verify_OtxStart(OtxStartType *otx_start) {
  int err = MOL2_OK;
  mol2_cursor_t input_cells = mol2_table_slice_by_index(&otx_start->cur, 0);
  CHECK(mol2_verify_fixed_size(&input_cells, MOL2_NUM_T_SIZE));
  mol2_cursor_t output_cells = mol2_table_slice_by_index(&otx_start->cur, 1);
  CHECK(mol2_verify_fixed_size(&output_cells, MOL2_NUM_T_SIZE));
  mol2_cursor_t cell_deps = mol2_table_slice_by_index(&otx_start->cur, 2);
  CHECK(mol2_verify_fixed_size(&cell_deps, MOL2_NUM_T_SIZE));
  mol2_cursor_t header_deps = mol2_table_slice_by_index(&otx_start->cur, 3);
  CHECK(mol2_verify_fixed_size(&header_deps, MOL2_NUM_T_SIZE));
exit:
  return err;
}

int get_union_id(mol2_cursor_t *cur, uint32_t *union_id) {
  uint32_t len = mol2_read_at(cur, (uint8_t *)union_id, MOL2_NUM_T_SIZE);
  if (len != MOL2_NUM_T_SIZE) {
    return MOL2_ERR_OVERFLOW;
  }

  return MOL2_OK;
}

int verify_WitnessLayout(WitnessLayoutType *witness) {
  int err = MOL2_OK;
  uint32_t union_id = 0;
  CHECK(get_union_id(&witness->cur, &union_id));

  switch (union_id) {
    case WitnessLayoutSighashAll: {
      SighashAllType sighash_all = witness->t->as_SighashAll(witness);
      return verify_SighashAll(&sighash_all);
    }
    case WitnessLayoutSighashAllOnly: {
      SighashAllOnlyType sighash_all_only =
          witness->t->as_SighashAllOnly(witness);
      return verify_SighashAllOnly(&sighash_all_only);
    }
    case WitnessLayoutOtx: {
      OtxType otx = witness->t->as_Otx(witness);
      return verify_Otx(&otx);
    }
    case WitnessLayoutOtxStart: {
      OtxStartType otx_start = witness->t->as_OtxStart(witness);
      return verify_OtxStart(&otx_start);
    }
    default: {
      return MOL2_ERR_UNKNOWN_ITEM;
    }
  }

exit:
  return err;
}

#endif  // MOLECULEC_C2_DECLARATION_ONLY

#endif
