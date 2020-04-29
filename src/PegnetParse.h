#ifndef _FAT_PARSE_H_
#define _FAT_PARSE_H_

#include "fctParse.h"
#include "fatParse.h"

//int toString(char a[], int len);

int processPegTx( char *inputaddress, int8_t *data, uint32_t length,
                       txContent_t *content) ;

#endif

