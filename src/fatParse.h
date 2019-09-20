#ifndef _FAT_PARSE_H_
#define _FAT_PARSE_H_

#include "fctParse.h"

parserStatus_e parseFatTx(uint8_t *data, uint32_t length,
                       txContent_t *content) ;

#endif

