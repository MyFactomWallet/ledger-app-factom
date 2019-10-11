#include "jsmn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fatParse.h"

/*
 * FAT 0/1 Json Parser
 */

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

static int jsonpartialeq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING &&
      strncmp(json + tok->start, s, MIN(tok->end - tok->start,strlen(s))) == 0) {
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

const int MINIMUM_VIABILITY = 10;

//JSMN_ERROR_PART == 
enum faterr {
     FAT_JSMN_ERROR_NOMEM = 1,
  /* Invalid character inside JSON string */
    FAT_JSMN_ERROR_INVAL = 2,
  /* The string is not a full JSON packet, more bytes expected */
    FAT_JSMN_ERROR_PART = 3,
  /* Not enough tokens were provided */
    FAT_ERROR_INPUT_EXPECTED = 4,
  /* Invalid character inside JSON string */
    FAT_INSUFFICIENT_IOM = 5,
    FAT_ERROR_INPUT_OBJECT_EXPECTED = 6,
    FAT_ERROR_INPUT_ADDRESS_EXPECTED = 7,
    FAT_ERROR_INPUT_AMOUNT_EXPECTED = 8,
    FAT_ERROR_INPUT_TOO_MANY_ADDRESS = 9,
    FAT_ERROR_OUTPUT_OBJECT_EXPECTED = 10,
    FAT_ERROR_OUTPUT_ADDRESS_EXPECTED = 11,
    FAT_ERROR_OUTPUT_AMOUNT_EXPECTED = 12,
    FAT_ERROR_OUTPUT_TOO_MANY_ADDRESS = 13,
    FAT_ERROR_INVALID_FCT_ADDRESS = 14,
    FAT_ERROR_JSON_OBJECT_NOT_FOUND = 15,
    FAT_ERROR_INVALID_JSON = 16
  /* The string is not a full JSON packet, more bytes expected */

};

int processFat0Outputs(jsmntok_t **tt, jsmntok_t *tend, uint8_t *d,uint32_t length,txContent_t *content)
{
    jsmntok_t *t = *tt;

    if ( t == tend )
    {
        return FAT_INSUFFICIENT_IOM;
    }
    if ( t->type != JSMN_OBJECT )
    {
        return FAT_ERROR_OUTPUT_OBJECT_EXPECTED;
    }

    ++t;

    content->header.outputcount = 0;

    while(jsonpartialeq(d, t, "FA1" ) == 0 ||
          jsonpartialeq(d, t, "FA2" ) == 0 ||
          jsonpartialeq(d, t, "FA3" ) == 0 )
    {
        char buff[128] = {0};


        if ( content->header.outputcount > MAX_OUTPUT_ADDRESSES)
        {
            return FAT_ERROR_OUTPUT_ADDRESS_EXPECTED;
        }

        if ( t->end - t->start != fct_address_length )
        {
            return FAT_ERROR_INVALID_FCT_ADDRESS;
        }

        ++t;

        if ( t->type != JSMN_PRIMITIVE )
        {
            return FAT_ERROR_OUTPUT_AMOUNT_EXPECTED;
        }


        //store off the pointer to the address
        content->outputs[content->header.outputcount].addr.fctaddr = d + (t-1)->start;

        int32_t val = toString(d+t->start, t->end - t->start);

        //convert to fatoshis
        content->outputs[content->header.outputcount].value = val * 100000000ul;

//        fprintf(stderr,"- Value: %.*s %ld \n", 52,
//               content->outputs[content->header.outputcount].addr.fctaddr,content->outputs[content->header.outputcount].value / 100000000 );

        ++t;

        ++content->header.outputcount;

    }
    *tt=t;
    return 0;
}

int toString(char a[], int len) {
  int c, sign, offset, n;
 
  if (a[0] == '-') {  // Handle negative integers
    sign = -1;
  }
 
  if (sign == -1) {  // Set starting position to convert
    offset = 1;
  }
  else {
    offset = 0;
  }
 
  n = 0;
 
  for (c = offset; a[c] != '\0' && c != len; c++) {
    n = n * 10 + a[c] - '0';
  }
 
  if (sign == -1) {
    n = -n;
  }
 
  return n;
}


int processFat0Inputs(jsmntok_t **tt, jsmntok_t *tend, uint8_t *d,uint32_t length, txContent_t *content)
{
    jsmntok_t *t = *tt;
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


    content->header.inputcount = 0;

    while(jsonpartialeq(d, t, "FA1" ) == 0 ||
          jsonpartialeq(d, t, "FA2" ) == 0 ||
          jsonpartialeq(d, t, "FA3" ) == 0 )
    {
        if ( content->header.inputcount > MAX_INPUT_ADDRESSES)
        {
            return FAT_ERROR_INPUT_TOO_MANY_ADDRESS;
        }

        if ( t->end - t->start != fct_address_length )
        {
            return FAT_ERROR_INVALID_FCT_ADDRESS;
        }

        //store off the pointer to the address
        content->inputs[content->header.inputcount].addr.fctaddr = d + t->start;
        ++t;

        if ( t->type != JSMN_PRIMITIVE )
        {
            return FAT_ERROR_INPUT_AMOUNT_EXPECTED;
        }


    

    
        int32_t val = toString(d+t->start, t->end - t->start);

        //convert to fatoshis
        content->inputs[content->header.inputcount].value = val * 100000000ul;


//        fprintf(stderr,"- Value: %.*s %ld \n", 52,
//               content->inputs[content->header.inputcount].addr.fctaddr,content->inputs[content->header.inputcount].value / 100000000 );

        ++t;

        ++content->header.inputcount;
    }

    *tt = t;
    return 0;
}


int processFat0Tx(int r, jsmntok_t *t, uint8_t *d, uint32_t length, txContent_t *content)
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

        if (jsoneq(d, t, "inputs") == 0)
        {
            ++t;
            
            ret = processFat0Inputs(&t, tend, d, length,content);
            if ( ret ) 
            {
                return ret;
            }
        }
        else if (jsoneq(d, t, "outputs") == 0)
        {
            ++t;
            ret = processFat0Outputs(&t, tend, d, length, content);
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

//int jsmnmain() {
//  int i;
//  int r;
//  jsmn_parser p;
//  jsmntok_t t[128]; /* We expect no more than 128 tokens */
//  jsmntok_t *curtok = t;

//  jsmn_init(&p);
//  r = jsmn_parse(&p, JSON_STRING, strlen(JSON_STRING), t,
//                 sizeof(t) / sizeof(t[0]));
//  if (r < 0) {
//    printf("Failed to parse JSON: %d\n", r);
//    return 1;
//  }

//  /* Assume the top-level element is an object */
//  if (r < 1 || t[0].type != JSMN_OBJECT) {
//    printf("Object expected\n");
//    return 1;
//  }
//  processFatTx(r,t);
//  return 0;
//    for (i = 1; i < r; i++) {
//        fprintf(stderr,"  * %s\n", jsmn_types[t[i].type]);
//    }
//  /* Loop over all keys of the root object */
//  for (i = 1; i < r; i++) {
//    if (jsoneq(JSON_STRING, &t[i], "inputs") == 0) {
//        //i = processInputs(r,t);
//    } else if (jsoneq(JSON_STRING, &t[i], "outputs") == 0) {
//      /* We may additionally check if the value is either "true" or "false" */
////      fprintf(stderr,"- Outputs: %.*s\n", t[i + 1].end - t[i + 1].start,
////             JSON_STRING + t[i + 1].start);
//        if ( t[i].type != JSMN_OBJECT )
//        {
//            //process FA outputs
//            for(int j = 0; j < t[i + 1].size; ++j)
//            {
//                jsmntok_t *g = &t[i + j + 2];
//                fprintf(stderr,"  * %.*s\n", g->end - g->start, JSON_STRING + g->start);
//                //the token ^^
//                //the value __
//            }

//            i += t[i + 1].size + 1;
//            if ( t[i].type != JSMN_PRIMITIVE )
//            {
//                return -1;//return error.
//            }

//            fprintf(stderr,"- Inputs: %.*s\n", t[i + 1].end - t[i + 1].start,
//                   JSON_STRING + t[i + 1].start);
//            i += t[i + 1].size + 1;


//        }
//      i++;
//    } else if (jsoneq(JSON_STRING, &t[i], "uid") == 0) {
//      /* We may want to do strtol() here to get numeric value */
//      fprintf(stderr,"- UID: %.*s\n", t[i + 1].end - t[i + 1].start,
//             JSON_STRING + t[i + 1].start);
//      i++;
//    } else if (jsoneq(JSON_STRING, &t[i], "FA1") == 0 ||
//               jsoneq(JSON_STRING, &t[i], "FA2") == 0 ||
//               jsoneq(JSON_STRING, &t[i], "FA3") == 0 ) {
//      int j;
//      fprintf(stderr,"- Factoid Addresses:\n");
//      if (t[i + 1].type != JSMN_ARRAY) {
//        continue; /* We expect groups to be an array of strings */
//      }
//      for (j = 0; j < t[i + 1].size; j++) {
//        jsmntok_t *g = &t[i + j + 2];
//        fprintf(stderr,"  * %.*s\n", g->end - g->start, JSON_STRING + g->start);
//      }
//      i += t[i + 1].size + 1;
//    } else {
//      fprintf(stderr,"Unexpected key: %.*s\n", t[i].end - t[i].start,
//             JSON_STRING + t[i].start);
//    }
//  }
//  return EXIT_SUCCESS;
//}

int isSpace(char c)
{
    switch (c) {
        case ' ':
        case '\t':
        case '\n':
        case '\v':
        case '\f':
        case '\r':
            return 1;
    }
    return 0;    
}

int parseFat0TxContent(uint8_t *d, uint32_t length, txContent_t *content)
{
    int8_t *de = d;
    uint8_t valid = 0;
    uint32_t i = 0;
  
    //static const char *JSON_STRING =
    //    "{\"inputs\":{\"FA22de5NSG2FA2HmMaD4h8qSAZAJyztmmnwgLPghCQKoSekwYYct\":150},\"outputs\":{\"FA3nr5r54AKBZ9SLABS3JyRoGcWMVMTkePW9MECKM8shMg2pMagn\":150}}";

    //de = JSON_STRING;
    //length = strlen(JSON_STRING);  
//    return 0x6000 | i;
    
    for(i = 0; i < length; ++i )
    {
        if ( d[i] == '{')
        {
            //input better be next...
            for (uint32_t j = i+1; j < length; ++j )
            {
                if ( !isSpace(&d[j]) )
                {
                    static char *input = "\"inputs\"";
                    if ( strlen(input) > length-j )
                    {
                        continue;
                    }
                    
                    if ( strncmp(&d[j], input, strlen(input)) == 0 )
                    {
                        valid = 1;
                    }
                    break;
                }
            }
            if ( valid )
            {
                break;
            }
        }
    }
    
    if (valid == 0 )
    {
        return FAT_ERROR_INVALID_JSON;
    }
    
    de = &d[i];

    int r;
    jsmn_parser p;
    static jsmntok_t t[16]; /* We expect no more than 128 tokens */
    
    jsmntok_t *curtok = t;

    
    jsmn_init(&p);
    
    
    r = jsmn_parse(&p, de, length, t,
                   sizeof(t) / sizeof(t[0]));
    
    
    if (r < 0)
    {
        //printf("Failed to parse JSON: %d\n", r);
        return FAT_ERROR_INVALID_JSON;
    }

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT)
    {
        //printf("Object expected\n");
        return FAT_ERROR_JSON_OBJECT_NOT_FOUND;
    }
    
    return processFat0Tx(r,t, de, length,content);
}

int parseFatTxInternal(uint8_t *d, uint32_t length,
                                  txContent_t *content)
{

    //identify if a fat 0 or fat 1 transaction.

    return parseFat0TxContent(d,length, content);
//    uint32_t offset = 0;
//    parserStatus_e result = USTREAM_FAULT;
//    //TODO: Send in the transaction data in small chunks from jswrapper
//    //(not to exceed 255 bytes for each chunk)

//    //while (offset != length) {
//        if (offset > length) {
//            goto error;
//        }
//        uint8_t bytes = 0;
//        uint64_t dataType = varint_decode(&data[offset],length,&bytes);
//        offset += bytes;

//        switch (dataType) {
//        case FCTTX_HEADER_V2:
//            context->header.version = dataType;
//            result = parseTxV2(data, length, context, &offset);
//            break;
//        default:
//            //result = USTREAM_FAULT_INTERNAL;
//            return 0x6E00;//|(uint8_t)dataType;
//            goto error;
//        }
//        if (result != USTREAM_FINISHED) {
//            goto error;
//        }
//   // }

//error:
//    return result;
}

int parseFat0Tx(uint8_t *d, uint32_t length,
                       txContent_t *content) {
    int result = 0;
    initContent(content);    
    result = parseFat0TxContent(d,length, content);
    return result;
            /*
    BEGIN_TRY {
        TRY {
            initContent(content);
            result = parseTxInternal(data, length, content);
            return USTREAM_FINISHED;
        }
        CATCH_OTHER(e) {
            result = USTREAM_FAULT;
        }
        FINALLY {
        }
    }
    END_TRY;
    */
    return result;
}


int parseFat1Tx(uint8_t *d, uint32_t length,
                       txContent_t *content) {
    int result = 0;
    initContent(content);    
    result = parseFat0TxContent(d,length, content);
    return result;
            /*
    BEGIN_TRY {
        TRY {
            initContent(content);
            result = parseTxInternal(data, length, content);
            return USTREAM_FINISHED;
        }
        CATCH_OTHER(e) {
            result = USTREAM_FAULT;
        }
        FINALLY {
        }
    }
    END_TRY;
    */
    return result;
}