#ifndef _PEGNET_PARSE_H_
#define _PEGNET_PARSE_H_

#include "fctParse.h"
#include "fatParse.h"


int processPegTx(const char *inputaddress, int r, jsmntok_t *t, int8_t *d, uint32_t length, txContent_t *content);


#endif

