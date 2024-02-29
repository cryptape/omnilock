#ifndef __COBUILD_H__
#define __COBUILD_H__

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "molecule2_reader.h"
#include "mol2_utils.h"

typedef int (*ScriptEntryType)(const Env* env, const uint8_t* signing_message_hash, mol2_cursor_t seal);
int ckb_cobuild_entry(const Env* env, ScriptEntryType entry, bool* cobuild_enabled);
int ckb_cobuild_normal_entry(const Env* env, ScriptEntryType entry);

#endif
