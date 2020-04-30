#include "jsmn.h"
//#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fatParse.h"
#include "PegnetParse.h"

extern int isSpace(char c);
//int processFat1Tx(int r, jsmntok_t *t, int8_t *d, uint32_t length, txContent_t *content);
/*
 * FAT 0/1 Json Parser
 */

static int jsoneq(const int8_t *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp((char*)&json[tok->start], s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

static int jsonpartialeq(const int8_t *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING &&
      strncmp((char*)&json[tok->start], s, MIN((uint32_t)(tok->end - tok->start),strlen(s))) == 0) {
    return 0;
  }
  return -1;
}

/*
* JSMN_OBJECT  //whole tx
* JSMN_STRING  //input/output/metadata
* JSMN_OBJECT  //input object
* JSMN_STRING  //input address
* JSMN_PRIMITIVE //value
* JSMN_STRING  //output
* JSMN_OBJECT  //output object
* JSMN_STRING  //output address
* JSMN_PRIMITIVE //output value
*/

//{"version":1,"transactions":[{"input":{"address":"FA2BRbu43H91VPYcGhEdjGXCbt6wGMojXSYDxEsa4GSNRC14Gaaz","amount":10000000000,"type":"pFCT"},"conversion":"PEG"}]}
int processFat2Version(jsmntok_t **tt, jsmntok_t *tend, int8_t *d,uint32_t length,txContent_t *content)
{
    jsmntok_t *t = *tt;
    int version = 0;
    if ( t == tend )
    {
        return FAT_INSUFFICIENT_IOM;
    }
    if ( t->type != JSMN_PRIMITIVE )
    {
        return FAT_ERROR_VERSION_EXPECTED;
    }

    //only version 1 supported
    content->header.version = 0;
    if ( t->end - t->start == 1 )
    {
        content->header.version = d[t->start] - '0';
    }
    
    if ( content->header.version != 1 )
    {
	//we only support version 1 of the spec.
	return FAT_ERROR_UNSUPPORTED_VERSION;
    }

    //++t;
    *tt=t;
    return 0;
}

int processFat2Transfer(bool inputaddressfound, jsmntok_t **tt, jsmntok_t *tend, int8_t *d,uint32_t length,txContent_t *content)
{
    jsmntok_t *t = *tt;

    if ( t == tend )
    {
        return FAT_INSUFFICIENT_IOM;
    }

    if ( t->type != JSMN_STRING )
    {
        return FAT_ERROR_OUTPUT_OBJECT_EXPECTED;
    }

    ++t;

    content->header.outputcount = 0;

    if(jsonpartialeq(d, t, "FA1" ) == 0 ||
          jsonpartialeq(d, t, "FA2" ) == 0 ||
          jsonpartialeq(d, t, "FA3" ) == 0 )
    {

        if ( content->header.outputcount > MAX_OUTPUT_ADDRESSES)
        {
            return FAT_ERROR_OUTPUT_TOO_MANY_ADDRESS;
        }

        if ( (uint32_t)(t->end - t->start) != fct_address_length )
        {
            return FAT_ERROR_INVALID_FCT_ADDRESS;
        }

        if ( inputaddressfound )
        {
            //store off the pointer to the address
            content->outputs[content->header.outputcount].addr.fctaddr = d + t->start;
        }


        ++t;


        if ( t->type != JSMN_STRING )
        {
            return FAT_ERROR_OUTPUT_ADDRESS_EXPECTED;
        }

        if ( strncmp(d + t->start,"amount" , t->end - t->start) != 0 )
        {
            return FAT_ERROR_OUTPUT_ADDRESS_EXPECTED;
        }

        ++t;
        if ( t->type != JSMN_PRIMITIVE )
        {
            if ( inputaddressfound )
            {
                content->outputs[content->header.outputcount].addr.fctaddr = NULL;
            }
            return FAT_ERROR_OUTPUT_AMOUNT_EXPECTED;
        }


        if ( inputaddressfound )
        {
            //will need to convert to fatoshis
            content->outputs[content->header.outputcount].amt.fat.entry = &d[t->start];
            content->outputs[content->header.outputcount].amt.fat.size = t->end - t->start;
            ++content->header.outputcount;
        }
        //++t;


    }
    *tt=t;
    return 0;
}


int processFat2TransferArray(bool inputaddressfound, jsmntok_t **tt, jsmntok_t *tend, int8_t *d,uint32_t length,txContent_t *content)
{
    jsmntok_t *t = *tt;
    int ret = 0;
    int aend = t->end;
    int incount = 0;
    if ( t == tend )
    {
        return FAT_INSUFFICIENT_IOM;
    }
    if ( t->type != JSMN_ARRAY )
    {
        return FAT_ERROR_TRANSACTION_ARRAY_EXPECTED;
    }


    while ( t->start < aend && t->start != t->end )
    {
        ++incount;
        ++t;

        if ( t->type != JSMN_OBJECT )
        {
            return FAT_ERROR_TRANSACTION_OBJECT_EXPECTED;
        }

        ++t;
        if ( t->type != JSMN_STRING )
        {
            return FAT_ERROR_INPUT_EXPECTED;
        }

        //first expect address
        if (jsoneq((int8_t*)d, t, "address") != 0)
        {
            return FAT_ERROR_OUTPUT_ADDRESS_EXPECTED;
        }

        ret = processFat2Transfer(inputaddressfound, &t, tend, d, length, content);
        if ( ret )
        {
            return ret;
        }

        ++t;

    }
    *tt = t;
    return 0;
}

int processFat2Conversion(bool inputaddressfound, jsmntok_t **tt, jsmntok_t *tend, int8_t *d,uint32_t length,txContent_t *content)
{
    jsmntok_t *t = *tt;
    char buf[256];

    if ( t->type != JSMN_STRING )
    {
        return FAT_ERROR_TRANSACTION_CONVERSION_TYPE_EXPECTED;
    }

    if (inputaddressfound )
    {
        content->header.outputcount = 0;
        //convert to fatoshis
        content->outputs[content->header.outputcount].amt.fat.entry = NULL;
        content->outputs[content->header.outputcount].amt.fat.size = 0;
        content->outputs[content->header.outputcount].amt.fat.type = &d[t->start];
        content->outputs[content->header.outputcount].amt.fat.typesize = t->end - t->start;
        ++content->header.outputcount;
    }

    ++t;

    *tt=t;
    return 0;
}


int processFat2Input(char *inputaddress, jsmntok_t **tt, jsmntok_t *tend, int8_t *d,uint32_t length, txContent_t *content, bool *targetaddrfound)
{
    jsmntok_t *t = *tt;
    //bool targetaddrfound = false;
    if ( t == tend )
    {
        return FAT_INSUFFICIENT_IOM;
    }
    if ( t->type != JSMN_OBJECT )
    {
        return FAT_ERROR_INPUT_OBJECT_EXPECTED;
    }

    ++t;

    if ( t->type != JSMN_STRING )
    {
        return FAT_ERROR_INPUT_ADDRESS_EXPECTED;
    }

    if ( strncmp("address",d+t->start, t->end-t->start) != 0 )
    {
        return FAT_ERROR_INPUT_ADDRESS_EXPECTED;
    }

    ++t;


    if ( t->type != JSMN_STRING )
    {
        return FAT_ERROR_INPUT_ADDRESS_EXPECTED;
    }

    content->header.inputcount = 0;

    if(jsonpartialeq(d, t, "FA1" ) == 0 ||
          jsonpartialeq(d, t, "FA2" ) == 0 ||
          jsonpartialeq(d, t, "FA3" ) == 0 )
    {
        if ( content->header.inputcount > MAX_INPUT_ADDRESSES)
        {
            return FAT_ERROR_INPUT_TOO_MANY_ADDRESS;
        }

        if ( (uint32_t)(t->end - t->start) != fct_address_length )
        {
            return FAT_ERROR_INVALID_FCT_ADDRESS;
        }

        if( jsoneq(d,t,inputaddress) == 0 )
        {
            *targetaddrfound = true;
            //store off the pointer to the address
            //content->inputs[content->header.inputcount].addr.fctaddr = d + t->start;
            //don't need to store it because it is already known
            content->inputs[content->header.inputcount].addr.fctaddr = d + t->start;
        }

        ++t;

        if ( t->type != JSMN_STRING )
        {
            return FAT_ERROR_INPUT_AMOUNT_EXPECTED;
        }

        if ( strncmp("amount", d+t->start, t->end-t->start) != 0 )
        {
            return FAT_ERROR_INPUT_AMOUNT_EXPECTED;
        }

        ++t;

        if ( t->type != JSMN_PRIMITIVE )
        {
            return FAT_ERROR_INPUT_AMOUNT_EXPECTED;
        }

        if ( *targetaddrfound )
        {
            //store off information for input == this signing attempt...
            //will need to convert to fatoshis
            content->inputs[content->header.inputcount].amt.fat.type = NULL;
            content->inputs[content->header.inputcount].amt.fat.typesize = 0;
            content->inputs[content->header.inputcount].amt.fat.entry = &d[t->start];
            content->inputs[content->header.inputcount].amt.fat.size = t->end - t->start;//val * 100000000ul;
        }



//        fprintf(stderr,"- Value: %.*s %ld \n", 52,
//               content->inputs[content->header.inputcount].addr.fctaddr,content->inputs[content->header.inputcount].value / 100000000 );

        ++t;

        if ( t->type != JSMN_STRING )
        {
            return FAT_ERROR_TRANSACTION_PEGTYPE_EXPECTED;
        }

        if ( strncmp("type", d+t->start, t->end-t->start) != 0 )
        {
            return FAT_ERROR_TRANSACTION_PEGTYPE_EXPECTED;
        }

        ++t;

        if ( t->type != JSMN_STRING )
        {
            return FAT_ERROR_TRANSACTION_PEGTYPE_EXPECTED;
        }

        if ( *targetaddrfound )
        {

            //store off information for input == this signing attempt...
            //will need to convert to fatoshis downstream
            //db: test not storing inputs since we don't need them
            content->inputs[content->header.inputcount].amt.fat.type = &d[t->start];
            content->inputs[content->header.inputcount].amt.fat.typesize = t->end - t->start;
            ++content->header.inputcount;
        }

        ++t;

    }
    else
    {
        return FAT_ERROR_INPUT_ADDRESS_EXPECTED;
    }

    *tt = t;
    return 0;
}

int processTransactionsArray(const char *inputaddress, jsmntok_t **tt,  jsmntok_t *tend, int8_t *d, uint32_t length, txContent_t *content)
{
    jsmntok_t *t = *tt;
    int ret = 0;
    int aend = t->end;
    int incount = 0;
    bool haveconversion = 0;
    bool havetransfer = 0;
    bool inputaddressfound = false;
    if ( t == tend )
    {
        return FAT_INSUFFICIENT_IOM;
    }
    if ( t->type != JSMN_ARRAY )
    {
        return FAT_ERROR_TRANSACTION_ARRAY_EXPECTED;
    }


    while ( t->start < aend && t->start != t->end )
    {
        ++incount;

        ++t;

        if ( t->type != JSMN_OBJECT )
        {
            return FAT_ERROR_TRANSACTION_OBJECT_EXPECTED;
        }

        ++t;
        if ( t->type != JSMN_STRING )
        {
            return FAT_ERROR_INPUT_EXPECTED;
        }

        //first expect input
        if (jsoneq((int8_t*)d, t, "input") == 0)
        {
            ++t;
            ret = processFat2Input(inputaddress, &t, tend, d, length,content, &inputaddressfound);
            if ( ret )
            {
                return ret;
            }
        }
        //now expect conversion or transfer
        if (jsoneq((int8_t*)d, t, "conversion") == 0)
        {
            if ( haveconversion )
            {
                return FAT_ERROR_TRANSACTION_SPECIFIED_CONVERSION_ALREADY_SPECIFIED;
            }
            if ( havetransfer )
            {
                return FAT_ERROR_TRANSACTION_SPECIFIED_TRANSFER_ALREADY_SPECIFIED;
            }
            ++t;
            ret = processFat2Conversion(inputaddressfound, &t, tend, d, length, content);

            if ( ret )
            {
                return ret;
            }
            haveconversion = true;
        }
        else if (jsoneq((int8_t*)d, t, "transfers") == 0)
        {
            if ( haveconversion )
            {
                return FAT_ERROR_TRANSACTION_SPECIFIED_CONVERSION_ALREADY_SPECIFIED;
            }
            havetransfer = true;

            ++t;
            ret = processFat2TransferArray(inputaddressfound, &t, tend, d, length, content);

            if ( ret )
            {
                return ret;
            }
        }

    }


    *tt = t;
    return 0;
}

int processPegTx(const char *inputaddress, int r, jsmntok_t *t, int8_t *d, uint32_t length, txContent_t *content)
{
    //minimum viability for a fat transaction is 10 tokens
    if (r < 1 || t->type != JSMN_OBJECT) {
      //printf("Object expected\n");
      return FAT_INSUFFICIENT_IOM;
    }


    jsmntok_t *tend = &t[r-1];
    ++t;


    if ( t == tend )
    {
        return FAT_INSUFFICIENT_IOM;
    }

    int ret = 0;
    for ( ; t < tend;  )
    {
        if ( t->type != JSMN_STRING )
        {
            return tend - t; //FAT_ERROR_INPUT_EXPECTED;
        }
        if (jsoneq((int8_t*)d, t, "version") == 0)
        {

            ++t;

            ret = processFat2Version(&t, tend, d, length,content);
            if ( ret )
            {
                return ret;
            }
        }

        if (jsoneq((int8_t*)d, t, "transactions") == 0)
        {
            //expect array, so handle array of transactions

            ++t;
            ret = processTransactionsArray(inputaddress, &t, tend, d, length,content);
            if ( ret )
            {
                return ret;
            }
        }
        else //metadata or something else, don't care
        {
            ++t;
            continue;
        }
    }
    return 0;
}




