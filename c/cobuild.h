#ifndef __COBUILD_H__
#define __COBUILD_H__

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "molecule2_reader.h"

typedef int (*ScriptEntryType)(const uint8_t* signing_message_hash,
                               mol2_cursor_t seal, bool witness_existing);
int ckb_cobuild_entry(ScriptEntryType entry, bool* cobuild_enabled);
int ckb_cobuild_normal_entry(ScriptEntryType entry);

#endif
