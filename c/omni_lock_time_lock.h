#ifndef OMNI_LOCK_TIME_LOCK_H_
#define OMNI_LOCK_TIME_LOCK_H_

#include "ckb_utils.h"
#define ERROR_INCORRECT_SINCE_FLAGS (-23)
#define ERROR_INCORRECT_SINCE_VALUE (-24)

/* check since,
 for all inputs the since field must have the exactly same flags with the since
 constraint, and the value of since must greater or equals than the since
 constraint */
int check_since(uint64_t since) {
  size_t i = 0;
  uint64_t len = 0;
  uint64_t input_since;
  int ret;
  while (1) {
    len = sizeof(uint64_t);
    ret =
        ckb_load_input_by_field(&input_since, &len, 0, i,
                                CKB_SOURCE_GROUP_INPUT, CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS || len != sizeof(uint64_t)) {
      return ERROR_SYSCALL;
    }
    int comparable = 1;
    int cmp = ckb_since_cmp(since, input_since, &comparable);
    if (!comparable) {
      return ERROR_INCORRECT_SINCE_FLAGS;
    }
    if (cmp == 1) {
      return ERROR_INCORRECT_SINCE_VALUE;
    }
    i += 1;
  }
  return CKB_SUCCESS;
}

#endif  // OMNI_LOCK_TIME_LOCK_H_
