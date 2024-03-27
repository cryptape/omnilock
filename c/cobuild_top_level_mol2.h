
#ifndef _COBUILD_TOP_LEVEL_MOL2_API2_H_
#define _COBUILD_TOP_LEVEL_MOL2_API2_H_

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
struct WitnessLayoutType;
struct WitnessLayoutVTable;
struct WitnessLayoutVTable *GetWitnessLayoutVTable(void);
struct WitnessLayoutType make_WitnessLayout(mol2_cursor_t *cur);
uint32_t WitnessLayout_item_id_impl(struct WitnessLayoutType *);
struct SighashAllType WitnessLayout_as_SighashAll_impl(
    struct WitnessLayoutType *);
struct SighashAllOnlyType WitnessLayout_as_SighashAllOnly_impl(
    struct WitnessLayoutType *);
struct OtxType WitnessLayout_as_Otx_impl(struct WitnessLayoutType *);
struct OtxStartType WitnessLayout_as_OtxStart_impl(struct WitnessLayoutType *);

// ----definition-----------------
typedef struct WitnessLayoutVTable {
  uint32_t (*item_id)(struct WitnessLayoutType *);
  struct SighashAllType (*as_SighashAll)(struct WitnessLayoutType *);
  struct SighashAllOnlyType (*as_SighashAllOnly)(struct WitnessLayoutType *);
  struct OtxType (*as_Otx)(struct WitnessLayoutType *);
  struct OtxStartType (*as_OtxStart)(struct WitnessLayoutType *);
} WitnessLayoutVTable;
typedef struct WitnessLayoutType {
  mol2_cursor_t cur;
  WitnessLayoutVTable *t;
} WitnessLayoutType;

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// ----implementation-------------
struct WitnessLayoutType make_WitnessLayout(mol2_cursor_t *cur) {
  WitnessLayoutType ret;
  ret.cur = *cur;
  ret.t = GetWitnessLayoutVTable();
  return ret;
}
struct WitnessLayoutVTable *GetWitnessLayoutVTable(void) {
  static WitnessLayoutVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.item_id = WitnessLayout_item_id_impl;
  s_vtable.as_SighashAll = WitnessLayout_as_SighashAll_impl;
  s_vtable.as_SighashAllOnly = WitnessLayout_as_SighashAllOnly_impl;
  s_vtable.as_Otx = WitnessLayout_as_Otx_impl;
  s_vtable.as_OtxStart = WitnessLayout_as_OtxStart_impl;
  return &s_vtable;
}
uint32_t WitnessLayout_item_id_impl(WitnessLayoutType *this) {
  return mol2_unpack_number(&this->cur);
}
SighashAllType WitnessLayout_as_SighashAll_impl(WitnessLayoutType *this) {
  SighashAllType ret;
  mol2_union_t u = mol2_union_unpack(&this->cur);
  ret.cur = u.cursor;
  ret.t = GetSighashAllVTable();
  return ret;
}
SighashAllOnlyType WitnessLayout_as_SighashAllOnly_impl(
    WitnessLayoutType *this) {
  SighashAllOnlyType ret;
  mol2_union_t u = mol2_union_unpack(&this->cur);
  ret.cur = u.cursor;
  ret.t = GetSighashAllOnlyVTable();
  return ret;
}
OtxType WitnessLayout_as_Otx_impl(WitnessLayoutType *this) {
  OtxType ret;
  mol2_union_t u = mol2_union_unpack(&this->cur);
  ret.cur = u.cursor;
  ret.t = GetOtxVTable();
  return ret;
}
OtxStartType WitnessLayout_as_OtxStart_impl(WitnessLayoutType *this) {
  OtxStartType ret;
  mol2_union_t u = mol2_union_unpack(&this->cur);
  ret.cur = u.cursor;
  ret.t = GetOtxStartVTable();
  return ret;
}
#endif  // MOLECULEC_C2_DECLARATION_ONLY

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // _COBUILD_TOP_LEVEL_MOL2_API2_H_
