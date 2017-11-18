/*******************************************************************************
*   MyFactgomWallet
*   (c) 2017 MyFactomWallet
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "os.h"
#include "cx.h"
#include <stdbool.h>

#define MAX_BIP32_PATH 10
#define MAX_INPUT_ADDRESSES 1
#define MAX_OUTPUT_ADDRESSES 10
#define MAX_ECOUTPUT_ADDRESSES 10

typedef enum parserStatus_e {
    USTREAM_PROCESSING,
    USTREAM_FINISHED,
    USTREAM_FAULT = 0x6E00,
    USTREAM_FAULT_INPUT_COUNT = 0x6E01,
    USTREAM_FAULT_OUTPUT_COUNT = 0x6E02,
    USTREAM_FAULT_ECOUTPUT_COUNT = 0x6E03,
    USTREAM_FAULT_ADDRESS = 0x6E04,
    USTREAM_FAULT_PARSE = 0x6E05,
    USTREAM_FAULT_INTERNAL = 0x6E06
} parserStatus_e;

//header
typedef struct txContentHeader_t {
    uint8_t *version;
    uint8_t *timestamp_ms;
    uint64_t fee;
    uint8_t *inputcount;
    uint8_t *outputcount;
    uint8_t *ecpurchasecount;
} txContentHeader_t;

typedef struct txContentAddress_t {
    uint64_t value;
    uint8_t  *rcdhash;
} txContentAddress_t;


typedef struct RCD_t {
    uint8_t *type;
    uint8_t *publickey;
} RCD_t;

typedef struct txSignedRCD_t {
    RCD_t RCD[256];
    uint8_t signature[256];
    uint8_t signature_len; 
} txSignedRCD_t;


typedef struct txContent_t {
    txContentHeader_t header;
    uint32_t fees;
    txContentAddress_t inputs[MAX_INPUT_ADDRESSES];
    txContentAddress_t outputs[MAX_OUTPUT_ADDRESSES];
    txContentAddress_t ecpurchase[MAX_ECOUTPUT_ADDRESSES];
} txContent_t;



parserStatus_e parseTx(uint8_t *data, uint32_t length, 
		       uint8_t *amtsz, uint16_t amtszLength,
		       txContent_t *context);

