#ifndef __COBUILD_H__
#define __COBUILD_H__

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "molecule2_reader.h"

/**
 * return non-zero if the transaction doesn't have cobuild support.
 * signing_message_hash: signing message hash
 * seal: the seal. Same as WitnessArgs.lock with new name.
 */
int ckb_parse_message(uint8_t *signing_message_hash, mol2_cursor_t *seal);
#endif
