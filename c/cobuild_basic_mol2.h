
#ifndef _COBUILD_BASIC_MOL2_API2_H_
#define _COBUILD_BASIC_MOL2_API2_H_

#ifndef MOLECULEC2_VERSION
#define MOLECULEC2_VERSION 7002
#endif
#ifndef MOLECULE2_API_VERSION_MIN
#define MOLECULE2_API_VERSION_MIN 5000
#endif

#include "molecule2_reader.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// ----forward declaration--------
struct HashType;
struct HashVTable;
struct HashVTable *GetHashVTable(void);
struct HashType make_Hash(mol2_cursor_t *cur);
uint32_t Hash_len_impl(struct HashType *);
uint8_t Hash_get_impl(struct HashType *, uint32_t, bool *);
struct StringType;
struct StringVTable;
struct StringVTable *GetStringVTable(void);
struct StringType make_String(mol2_cursor_t *cur);
uint32_t String_len_impl(struct StringType *);
uint8_t String_get_impl(struct StringType *, uint32_t, bool *);
struct Uint32OptType;
struct Uint32OptVTable;
struct Uint32OptVTable *GetUint32OptVTable(void);
struct Uint32OptType make_Uint32Opt(mol2_cursor_t *cur);
bool Uint32Opt_is_none_impl(struct Uint32OptType *);
bool Uint32Opt_is_some_impl(struct Uint32OptType *);
uint32_t Uint32Opt_unwrap_impl(struct Uint32OptType *);
struct ActionType;
struct ActionVTable;
struct ActionVTable *GetActionVTable(void);
struct ActionType make_Action(mol2_cursor_t *cur);
mol2_cursor_t Action_get_script_info_hash_impl(struct ActionType *);
mol2_cursor_t Action_get_script_hash_impl(struct ActionType *);
mol2_cursor_t Action_get_data_impl(struct ActionType *);
struct ActionVecType;
struct ActionVecVTable;
struct ActionVecVTable *GetActionVecVTable(void);
struct ActionVecType make_ActionVec(mol2_cursor_t *cur);
uint32_t ActionVec_len_impl(struct ActionVecType *);
struct ActionType ActionVec_get_impl(struct ActionVecType *, uint32_t, bool *);
struct MessageType;
struct MessageVTable;
struct MessageVTable *GetMessageVTable(void);
struct MessageType make_Message(mol2_cursor_t *cur);
struct ActionVecType Message_get_actions_impl(struct MessageType *);
struct ScriptInfoType;
struct ScriptInfoVTable;
struct ScriptInfoVTable *GetScriptInfoVTable(void);
struct ScriptInfoType make_ScriptInfo(mol2_cursor_t *cur);
mol2_cursor_t ScriptInfo_get_name_impl(struct ScriptInfoType *);
mol2_cursor_t ScriptInfo_get_url_impl(struct ScriptInfoType *);
mol2_cursor_t ScriptInfo_get_script_hash_impl(struct ScriptInfoType *);
mol2_cursor_t ScriptInfo_get_schema_impl(struct ScriptInfoType *);
mol2_cursor_t ScriptInfo_get_message_type_impl(struct ScriptInfoType *);
struct ScriptInfoVecType;
struct ScriptInfoVecVTable;
struct ScriptInfoVecVTable *GetScriptInfoVecVTable(void);
struct ScriptInfoVecType make_ScriptInfoVec(mol2_cursor_t *cur);
uint32_t ScriptInfoVec_len_impl(struct ScriptInfoVecType *);
struct ScriptInfoType ScriptInfoVec_get_impl(struct ScriptInfoVecType *,
                                             uint32_t, bool *);
struct ResolvedInputsType;
struct ResolvedInputsVTable;
struct ResolvedInputsVTable *GetResolvedInputsVTable(void);
struct ResolvedInputsType make_ResolvedInputs(mol2_cursor_t *cur);
struct CellOutputVecType ResolvedInputs_get_outputs_impl(
    struct ResolvedInputsType *);
struct BytesVecType ResolvedInputs_get_outputs_data_impl(
    struct ResolvedInputsType *);
struct BuildingPacketV1Type;
struct BuildingPacketV1VTable;
struct BuildingPacketV1VTable *GetBuildingPacketV1VTable(void);
struct BuildingPacketV1Type make_BuildingPacketV1(mol2_cursor_t *cur);
struct MessageType BuildingPacketV1_get_message_impl(
    struct BuildingPacketV1Type *);
struct TransactionType BuildingPacketV1_get_payload_impl(
    struct BuildingPacketV1Type *);
struct ResolvedInputsType BuildingPacketV1_get_resolved_inputs_impl(
    struct BuildingPacketV1Type *);
struct Uint32OptType BuildingPacketV1_get_change_output_impl(
    struct BuildingPacketV1Type *);
struct ScriptInfoVecType BuildingPacketV1_get_script_infos_impl(
    struct BuildingPacketV1Type *);
struct ActionVecType BuildingPacketV1_get_lock_actions_impl(
    struct BuildingPacketV1Type *);
struct BuildingPacketType;
struct BuildingPacketVTable;
struct BuildingPacketVTable *GetBuildingPacketVTable(void);
struct BuildingPacketType make_BuildingPacket(mol2_cursor_t *cur);
uint32_t BuildingPacket_item_id_impl(struct BuildingPacketType *);
struct BuildingPacketV1Type BuildingPacket_as_BuildingPacketV1_impl(
    struct BuildingPacketType *);
struct SighashAllType;
struct SighashAllVTable;
struct SighashAllVTable *GetSighashAllVTable(void);
struct SighashAllType make_SighashAll(mol2_cursor_t *cur);
struct MessageType SighashAll_get_message_impl(struct SighashAllType *);
mol2_cursor_t SighashAll_get_seal_impl(struct SighashAllType *);
struct SighashAllOnlyType;
struct SighashAllOnlyVTable;
struct SighashAllOnlyVTable *GetSighashAllOnlyVTable(void);
struct SighashAllOnlyType make_SighashAllOnly(mol2_cursor_t *cur);
mol2_cursor_t SighashAllOnly_get_seal_impl(struct SighashAllOnlyType *);
struct SealPairType;
struct SealPairVTable;
struct SealPairVTable *GetSealPairVTable(void);
struct SealPairType make_SealPair(mol2_cursor_t *cur);
mol2_cursor_t SealPair_get_script_hash_impl(struct SealPairType *);
mol2_cursor_t SealPair_get_seal_impl(struct SealPairType *);
struct SealPairVecType;
struct SealPairVecVTable;
struct SealPairVecVTable *GetSealPairVecVTable(void);
struct SealPairVecType make_SealPairVec(mol2_cursor_t *cur);
uint32_t SealPairVec_len_impl(struct SealPairVecType *);
struct SealPairType SealPairVec_get_impl(struct SealPairVecType *, uint32_t,
                                         bool *);
struct OtxStartType;
struct OtxStartVTable;
struct OtxStartVTable *GetOtxStartVTable(void);
struct OtxStartType make_OtxStart(mol2_cursor_t *cur);
uint32_t OtxStart_get_start_input_cell_impl(struct OtxStartType *);
uint32_t OtxStart_get_start_output_cell_impl(struct OtxStartType *);
uint32_t OtxStart_get_start_cell_deps_impl(struct OtxStartType *);
uint32_t OtxStart_get_start_header_deps_impl(struct OtxStartType *);
struct OtxType;
struct OtxVTable;
struct OtxVTable *GetOtxVTable(void);
struct OtxType make_Otx(mol2_cursor_t *cur);
uint32_t Otx_get_input_cells_impl(struct OtxType *);
uint32_t Otx_get_output_cells_impl(struct OtxType *);
uint32_t Otx_get_cell_deps_impl(struct OtxType *);
uint32_t Otx_get_header_deps_impl(struct OtxType *);
struct MessageType Otx_get_message_impl(struct OtxType *);
struct SealPairVecType Otx_get_seals_impl(struct OtxType *);

// ----definition-----------------
typedef struct HashVTable {
  uint32_t (*len)(struct HashType *);
  uint8_t (*get)(struct HashType *, uint32_t, bool *);
} HashVTable;
typedef struct HashType {
  mol2_cursor_t cur;
  HashVTable *t;
} HashType;

typedef struct StringVTable {
  uint32_t (*len)(struct StringType *);
  uint8_t (*get)(struct StringType *, uint32_t, bool *);
} StringVTable;
typedef struct StringType {
  mol2_cursor_t cur;
  StringVTable *t;
} StringType;

typedef struct Uint32OptVTable {
  bool (*is_none)(struct Uint32OptType *);
  bool (*is_some)(struct Uint32OptType *);
  uint32_t (*unwrap)(struct Uint32OptType *);
} Uint32OptVTable;
typedef struct Uint32OptType {
  mol2_cursor_t cur;
  Uint32OptVTable *t;
} Uint32OptType;

typedef struct ActionVTable {
  mol2_cursor_t (*script_info_hash)(struct ActionType *);
  mol2_cursor_t (*script_hash)(struct ActionType *);
  mol2_cursor_t (*data)(struct ActionType *);
} ActionVTable;
typedef struct ActionType {
  mol2_cursor_t cur;
  ActionVTable *t;
} ActionType;

typedef struct ActionVecVTable {
  uint32_t (*len)(struct ActionVecType *);
  struct ActionType (*get)(struct ActionVecType *, uint32_t, bool *);
} ActionVecVTable;
typedef struct ActionVecType {
  mol2_cursor_t cur;
  ActionVecVTable *t;
} ActionVecType;

typedef struct MessageVTable {
  struct ActionVecType (*actions)(struct MessageType *);
} MessageVTable;
typedef struct MessageType {
  mol2_cursor_t cur;
  MessageVTable *t;
} MessageType;

typedef struct ScriptInfoVTable {
  mol2_cursor_t (*name)(struct ScriptInfoType *);
  mol2_cursor_t (*url)(struct ScriptInfoType *);
  mol2_cursor_t (*script_hash)(struct ScriptInfoType *);
  mol2_cursor_t (*schema)(struct ScriptInfoType *);
  mol2_cursor_t (*message_type)(struct ScriptInfoType *);
} ScriptInfoVTable;
typedef struct ScriptInfoType {
  mol2_cursor_t cur;
  ScriptInfoVTable *t;
} ScriptInfoType;

typedef struct ScriptInfoVecVTable {
  uint32_t (*len)(struct ScriptInfoVecType *);
  struct ScriptInfoType (*get)(struct ScriptInfoVecType *, uint32_t, bool *);
} ScriptInfoVecVTable;
typedef struct ScriptInfoVecType {
  mol2_cursor_t cur;
  ScriptInfoVecVTable *t;
} ScriptInfoVecType;

typedef struct ResolvedInputsVTable {
  struct CellOutputVecType (*outputs)(struct ResolvedInputsType *);
  struct BytesVecType (*outputs_data)(struct ResolvedInputsType *);
} ResolvedInputsVTable;
typedef struct ResolvedInputsType {
  mol2_cursor_t cur;
  ResolvedInputsVTable *t;
} ResolvedInputsType;

typedef struct BuildingPacketV1VTable {
  struct MessageType (*message)(struct BuildingPacketV1Type *);
  struct TransactionType (*payload)(struct BuildingPacketV1Type *);
  struct ResolvedInputsType (*resolved_inputs)(struct BuildingPacketV1Type *);
  struct Uint32OptType (*change_output)(struct BuildingPacketV1Type *);
  struct ScriptInfoVecType (*script_infos)(struct BuildingPacketV1Type *);
  struct ActionVecType (*lock_actions)(struct BuildingPacketV1Type *);
} BuildingPacketV1VTable;
typedef struct BuildingPacketV1Type {
  mol2_cursor_t cur;
  BuildingPacketV1VTable *t;
} BuildingPacketV1Type;

typedef struct BuildingPacketVTable {
  uint32_t (*item_id)(struct BuildingPacketType *);
  struct BuildingPacketV1Type (*as_BuildingPacketV1)(
      struct BuildingPacketType *);
} BuildingPacketVTable;
typedef struct BuildingPacketType {
  mol2_cursor_t cur;
  BuildingPacketVTable *t;
} BuildingPacketType;

typedef struct SighashAllVTable {
  struct MessageType (*message)(struct SighashAllType *);
  mol2_cursor_t (*seal)(struct SighashAllType *);
} SighashAllVTable;
typedef struct SighashAllType {
  mol2_cursor_t cur;
  SighashAllVTable *t;
} SighashAllType;

typedef struct SighashAllOnlyVTable {
  mol2_cursor_t (*seal)(struct SighashAllOnlyType *);
} SighashAllOnlyVTable;
typedef struct SighashAllOnlyType {
  mol2_cursor_t cur;
  SighashAllOnlyVTable *t;
} SighashAllOnlyType;

typedef struct SealPairVTable {
  mol2_cursor_t (*script_hash)(struct SealPairType *);
  mol2_cursor_t (*seal)(struct SealPairType *);
} SealPairVTable;
typedef struct SealPairType {
  mol2_cursor_t cur;
  SealPairVTable *t;
} SealPairType;

typedef struct SealPairVecVTable {
  uint32_t (*len)(struct SealPairVecType *);
  struct SealPairType (*get)(struct SealPairVecType *, uint32_t, bool *);
} SealPairVecVTable;
typedef struct SealPairVecType {
  mol2_cursor_t cur;
  SealPairVecVTable *t;
} SealPairVecType;

typedef struct OtxStartVTable {
  uint32_t (*start_input_cell)(struct OtxStartType *);
  uint32_t (*start_output_cell)(struct OtxStartType *);
  uint32_t (*start_cell_deps)(struct OtxStartType *);
  uint32_t (*start_header_deps)(struct OtxStartType *);
} OtxStartVTable;
typedef struct OtxStartType {
  mol2_cursor_t cur;
  OtxStartVTable *t;
} OtxStartType;

typedef struct OtxVTable {
  uint32_t (*input_cells)(struct OtxType *);
  uint32_t (*output_cells)(struct OtxType *);
  uint32_t (*cell_deps)(struct OtxType *);
  uint32_t (*header_deps)(struct OtxType *);
  struct MessageType (*message)(struct OtxType *);
  struct SealPairVecType (*seals)(struct OtxType *);
} OtxVTable;
typedef struct OtxType {
  mol2_cursor_t cur;
  OtxVTable *t;
} OtxType;

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// ----implementation-------------
struct HashType make_Hash(mol2_cursor_t *cur) {
  HashType ret;
  ret.cur = *cur;
  ret.t = GetHashVTable();
  return ret;
}
struct HashVTable *GetHashVTable(void) {
  static HashVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = Hash_len_impl;
  s_vtable.get = Hash_get_impl;
  return &s_vtable;
}
uint32_t Hash_len_impl(HashType *this) { return 32; }
uint8_t Hash_get_impl(HashType *this, uint32_t index, bool *existing) {
  uint8_t ret = {0};
  mol2_cursor_res_t res = mol2_slice_by_offset2(&this->cur, 1 * index, 1);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret = convert_to_Uint8(&res.cur);
  return ret;
}
struct StringType make_String(mol2_cursor_t *cur) {
  StringType ret;
  ret.cur = *cur;
  ret.t = GetStringVTable();
  return ret;
}
struct StringVTable *GetStringVTable(void) {
  static StringVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = String_len_impl;
  s_vtable.get = String_get_impl;
  return &s_vtable;
}
uint32_t String_len_impl(StringType *this) {
  return mol2_fixvec_length(&this->cur);
}
uint8_t String_get_impl(StringType *this, uint32_t index, bool *existing) {
  uint8_t ret = {0};
  mol2_cursor_res_t res = mol2_fixvec_slice_by_index(&this->cur, 1, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret = convert_to_Uint8(&res.cur);
  return ret;
}
struct Uint32OptType make_Uint32Opt(mol2_cursor_t *cur) {
  Uint32OptType ret;
  ret.cur = *cur;
  ret.t = GetUint32OptVTable();
  return ret;
}
struct Uint32OptVTable *GetUint32OptVTable(void) {
  static Uint32OptVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.is_none = Uint32Opt_is_none_impl;
  s_vtable.is_some = Uint32Opt_is_some_impl;
  s_vtable.unwrap = Uint32Opt_unwrap_impl;
  return &s_vtable;
}
bool Uint32Opt_is_none_impl(Uint32OptType *this) {
  return mol2_option_is_none(&this->cur);
}
bool Uint32Opt_is_some_impl(Uint32OptType *this) {
  return !mol2_option_is_none(&this->cur);
}
uint32_t Uint32Opt_unwrap_impl(Uint32OptType *this) {
  uint32_t ret;
  ret = convert_to_Uint32(&this->cur);
  return ret;
}
struct ActionType make_Action(mol2_cursor_t *cur) {
  ActionType ret;
  ret.cur = *cur;
  ret.t = GetActionVTable();
  return ret;
}
struct ActionVTable *GetActionVTable(void) {
  static ActionVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.script_info_hash = Action_get_script_info_hash_impl;
  s_vtable.script_hash = Action_get_script_hash_impl;
  s_vtable.data = Action_get_data_impl;
  return &s_vtable;
}
mol2_cursor_t Action_get_script_info_hash_impl(ActionType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t Action_get_script_hash_impl(ActionType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t Action_get_data_impl(ActionType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 2);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
struct ActionVecType make_ActionVec(mol2_cursor_t *cur) {
  ActionVecType ret;
  ret.cur = *cur;
  ret.t = GetActionVecVTable();
  return ret;
}
struct ActionVecVTable *GetActionVecVTable(void) {
  static ActionVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = ActionVec_len_impl;
  s_vtable.get = ActionVec_get_impl;
  return &s_vtable;
}
uint32_t ActionVec_len_impl(ActionVecType *this) {
  return mol2_dynvec_length(&this->cur);
}
ActionType ActionVec_get_impl(ActionVecType *this, uint32_t index,
                              bool *existing) {
  ActionType ret = {0};
  mol2_cursor_res_t res = mol2_dynvec_slice_by_index(&this->cur, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret.cur = res.cur;
  ret.t = GetActionVTable();
  return ret;
}
struct MessageType make_Message(mol2_cursor_t *cur) {
  MessageType ret;
  ret.cur = *cur;
  ret.t = GetMessageVTable();
  return ret;
}
struct MessageVTable *GetMessageVTable(void) {
  static MessageVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.actions = Message_get_actions_impl;
  return &s_vtable;
}
ActionVecType Message_get_actions_impl(MessageType *this) {
  ActionVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetActionVecVTable();
  return ret;
}
struct ScriptInfoType make_ScriptInfo(mol2_cursor_t *cur) {
  ScriptInfoType ret;
  ret.cur = *cur;
  ret.t = GetScriptInfoVTable();
  return ret;
}
struct ScriptInfoVTable *GetScriptInfoVTable(void) {
  static ScriptInfoVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.name = ScriptInfo_get_name_impl;
  s_vtable.url = ScriptInfo_get_url_impl;
  s_vtable.script_hash = ScriptInfo_get_script_hash_impl;
  s_vtable.schema = ScriptInfo_get_schema_impl;
  s_vtable.message_type = ScriptInfo_get_message_type_impl;
  return &s_vtable;
}
mol2_cursor_t ScriptInfo_get_name_impl(ScriptInfoType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
mol2_cursor_t ScriptInfo_get_url_impl(ScriptInfoType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
mol2_cursor_t ScriptInfo_get_script_hash_impl(ScriptInfoType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 2);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t ScriptInfo_get_schema_impl(ScriptInfoType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 3);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
mol2_cursor_t ScriptInfo_get_message_type_impl(ScriptInfoType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 4);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
struct ScriptInfoVecType make_ScriptInfoVec(mol2_cursor_t *cur) {
  ScriptInfoVecType ret;
  ret.cur = *cur;
  ret.t = GetScriptInfoVecVTable();
  return ret;
}
struct ScriptInfoVecVTable *GetScriptInfoVecVTable(void) {
  static ScriptInfoVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = ScriptInfoVec_len_impl;
  s_vtable.get = ScriptInfoVec_get_impl;
  return &s_vtable;
}
uint32_t ScriptInfoVec_len_impl(ScriptInfoVecType *this) {
  return mol2_dynvec_length(&this->cur);
}
ScriptInfoType ScriptInfoVec_get_impl(ScriptInfoVecType *this, uint32_t index,
                                      bool *existing) {
  ScriptInfoType ret = {0};
  mol2_cursor_res_t res = mol2_dynvec_slice_by_index(&this->cur, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret.cur = res.cur;
  ret.t = GetScriptInfoVTable();
  return ret;
}
struct ResolvedInputsType make_ResolvedInputs(mol2_cursor_t *cur) {
  ResolvedInputsType ret;
  ret.cur = *cur;
  ret.t = GetResolvedInputsVTable();
  return ret;
}
struct ResolvedInputsVTable *GetResolvedInputsVTable(void) {
  static ResolvedInputsVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.outputs = ResolvedInputs_get_outputs_impl;
  s_vtable.outputs_data = ResolvedInputs_get_outputs_data_impl;
  return &s_vtable;
}
CellOutputVecType ResolvedInputs_get_outputs_impl(ResolvedInputsType *this) {
  CellOutputVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetCellOutputVecVTable();
  return ret;
}
BytesVecType ResolvedInputs_get_outputs_data_impl(ResolvedInputsType *this) {
  BytesVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetBytesVecVTable();
  return ret;
}
struct BuildingPacketV1Type make_BuildingPacketV1(mol2_cursor_t *cur) {
  BuildingPacketV1Type ret;
  ret.cur = *cur;
  ret.t = GetBuildingPacketV1VTable();
  return ret;
}
struct BuildingPacketV1VTable *GetBuildingPacketV1VTable(void) {
  static BuildingPacketV1VTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.message = BuildingPacketV1_get_message_impl;
  s_vtable.payload = BuildingPacketV1_get_payload_impl;
  s_vtable.resolved_inputs = BuildingPacketV1_get_resolved_inputs_impl;
  s_vtable.change_output = BuildingPacketV1_get_change_output_impl;
  s_vtable.script_infos = BuildingPacketV1_get_script_infos_impl;
  s_vtable.lock_actions = BuildingPacketV1_get_lock_actions_impl;
  return &s_vtable;
}
MessageType BuildingPacketV1_get_message_impl(BuildingPacketV1Type *this) {
  MessageType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetMessageVTable();
  return ret;
}
TransactionType BuildingPacketV1_get_payload_impl(BuildingPacketV1Type *this) {
  TransactionType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetTransactionVTable();
  return ret;
}
ResolvedInputsType BuildingPacketV1_get_resolved_inputs_impl(
    BuildingPacketV1Type *this) {
  ResolvedInputsType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 2);
  ret.cur = cur;
  ret.t = GetResolvedInputsVTable();
  return ret;
}
Uint32OptType BuildingPacketV1_get_change_output_impl(
    BuildingPacketV1Type *this) {
  Uint32OptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 3);
  ret.cur = cur;
  ret.t = GetUint32OptVTable();
  return ret;
}
ScriptInfoVecType BuildingPacketV1_get_script_infos_impl(
    BuildingPacketV1Type *this) {
  ScriptInfoVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 4);
  ret.cur = cur;
  ret.t = GetScriptInfoVecVTable();
  return ret;
}
ActionVecType BuildingPacketV1_get_lock_actions_impl(
    BuildingPacketV1Type *this) {
  ActionVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 5);
  ret.cur = cur;
  ret.t = GetActionVecVTable();
  return ret;
}
struct BuildingPacketType make_BuildingPacket(mol2_cursor_t *cur) {
  BuildingPacketType ret;
  ret.cur = *cur;
  ret.t = GetBuildingPacketVTable();
  return ret;
}
struct BuildingPacketVTable *GetBuildingPacketVTable(void) {
  static BuildingPacketVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.item_id = BuildingPacket_item_id_impl;
  s_vtable.as_BuildingPacketV1 = BuildingPacket_as_BuildingPacketV1_impl;
  return &s_vtable;
}
uint32_t BuildingPacket_item_id_impl(BuildingPacketType *this) {
  return mol2_unpack_number(&this->cur);
}
BuildingPacketV1Type BuildingPacket_as_BuildingPacketV1_impl(
    BuildingPacketType *this) {
  BuildingPacketV1Type ret;
  mol2_union_t u = mol2_union_unpack(&this->cur);
  ret.cur = u.cursor;
  ret.t = GetBuildingPacketV1VTable();
  return ret;
}
struct SighashAllType make_SighashAll(mol2_cursor_t *cur) {
  SighashAllType ret;
  ret.cur = *cur;
  ret.t = GetSighashAllVTable();
  return ret;
}
struct SighashAllVTable *GetSighashAllVTable(void) {
  static SighashAllVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.message = SighashAll_get_message_impl;
  s_vtable.seal = SighashAll_get_seal_impl;
  return &s_vtable;
}
MessageType SighashAll_get_message_impl(SighashAllType *this) {
  MessageType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetMessageVTable();
  return ret;
}
mol2_cursor_t SighashAll_get_seal_impl(SighashAllType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
struct SighashAllOnlyType make_SighashAllOnly(mol2_cursor_t *cur) {
  SighashAllOnlyType ret;
  ret.cur = *cur;
  ret.t = GetSighashAllOnlyVTable();
  return ret;
}
struct SighashAllOnlyVTable *GetSighashAllOnlyVTable(void) {
  static SighashAllOnlyVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.seal = SighashAllOnly_get_seal_impl;
  return &s_vtable;
}
mol2_cursor_t SighashAllOnly_get_seal_impl(SighashAllOnlyType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
struct SealPairType make_SealPair(mol2_cursor_t *cur) {
  SealPairType ret;
  ret.cur = *cur;
  ret.t = GetSealPairVTable();
  return ret;
}
struct SealPairVTable *GetSealPairVTable(void) {
  static SealPairVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.script_hash = SealPair_get_script_hash_impl;
  s_vtable.seal = SealPair_get_seal_impl;
  return &s_vtable;
}
mol2_cursor_t SealPair_get_script_hash_impl(SealPairType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t SealPair_get_seal_impl(SealPairType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
struct SealPairVecType make_SealPairVec(mol2_cursor_t *cur) {
  SealPairVecType ret;
  ret.cur = *cur;
  ret.t = GetSealPairVecVTable();
  return ret;
}
struct SealPairVecVTable *GetSealPairVecVTable(void) {
  static SealPairVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = SealPairVec_len_impl;
  s_vtable.get = SealPairVec_get_impl;
  return &s_vtable;
}
uint32_t SealPairVec_len_impl(SealPairVecType *this) {
  return mol2_dynvec_length(&this->cur);
}
SealPairType SealPairVec_get_impl(SealPairVecType *this, uint32_t index,
                                  bool *existing) {
  SealPairType ret = {0};
  mol2_cursor_res_t res = mol2_dynvec_slice_by_index(&this->cur, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret.cur = res.cur;
  ret.t = GetSealPairVTable();
  return ret;
}
struct OtxStartType make_OtxStart(mol2_cursor_t *cur) {
  OtxStartType ret;
  ret.cur = *cur;
  ret.t = GetOtxStartVTable();
  return ret;
}
struct OtxStartVTable *GetOtxStartVTable(void) {
  static OtxStartVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.start_input_cell = OtxStart_get_start_input_cell_impl;
  s_vtable.start_output_cell = OtxStart_get_start_output_cell_impl;
  s_vtable.start_cell_deps = OtxStart_get_start_cell_deps_impl;
  s_vtable.start_header_deps = OtxStart_get_start_header_deps_impl;
  return &s_vtable;
}
uint32_t OtxStart_get_start_input_cell_impl(OtxStartType *this) {
  uint32_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_Uint32(&ret2);
  return ret;
}
uint32_t OtxStart_get_start_output_cell_impl(OtxStartType *this) {
  uint32_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_Uint32(&ret2);
  return ret;
}
uint32_t OtxStart_get_start_cell_deps_impl(OtxStartType *this) {
  uint32_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 2);
  ret = convert_to_Uint32(&ret2);
  return ret;
}
uint32_t OtxStart_get_start_header_deps_impl(OtxStartType *this) {
  uint32_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 3);
  ret = convert_to_Uint32(&ret2);
  return ret;
}
struct OtxType make_Otx(mol2_cursor_t *cur) {
  OtxType ret;
  ret.cur = *cur;
  ret.t = GetOtxVTable();
  return ret;
}
struct OtxVTable *GetOtxVTable(void) {
  static OtxVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.input_cells = Otx_get_input_cells_impl;
  s_vtable.output_cells = Otx_get_output_cells_impl;
  s_vtable.cell_deps = Otx_get_cell_deps_impl;
  s_vtable.header_deps = Otx_get_header_deps_impl;
  s_vtable.message = Otx_get_message_impl;
  s_vtable.seals = Otx_get_seals_impl;
  return &s_vtable;
}
uint32_t Otx_get_input_cells_impl(OtxType *this) {
  uint32_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_Uint32(&ret2);
  return ret;
}
uint32_t Otx_get_output_cells_impl(OtxType *this) {
  uint32_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_Uint32(&ret2);
  return ret;
}
uint32_t Otx_get_cell_deps_impl(OtxType *this) {
  uint32_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 2);
  ret = convert_to_Uint32(&ret2);
  return ret;
}
uint32_t Otx_get_header_deps_impl(OtxType *this) {
  uint32_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 3);
  ret = convert_to_Uint32(&ret2);
  return ret;
}
MessageType Otx_get_message_impl(OtxType *this) {
  MessageType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 4);
  ret.cur = cur;
  ret.t = GetMessageVTable();
  return ret;
}
SealPairVecType Otx_get_seals_impl(OtxType *this) {
  SealPairVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 5);
  ret.cur = cur;
  ret.t = GetSealPairVecVTable();
  return ret;
}
#endif  // MOLECULEC_C2_DECLARATION_ONLY

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // _COBUILD_BASIC_MOL2_API2_H_
