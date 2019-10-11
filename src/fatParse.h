#ifndef _FAT_PARSE_H_
#define _FAT_PARSE_H_

#include "fctParse.h"

int toString(char a[], int len);
int parseFat0Tx(uint8_t *data, uint32_t length,
                       txContent_t *content) ;
                       
int parseFat1Tx(uint8_t *data, uint32_t length,
                       txContent_t *content) ;

#endif

