/*******************************************************************************
*   Factom Wallet
*   (c) 2018 The Factoid Authority
*            ledger@factoid.org
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

#ifndef _FCT_UTIL_H_
#define _FCT_UTIL_H_

#include <stdint.h>
#include "os.h"
#include "cx.h"


#define EC_ENTRY_HASH_LENGTH 32
#define EC_PUBLIC_KEY_LENGTH 32
#define CHAIN_WELD_LENGTH 32
#define CHAIN_HASH_LENGTH 32

typedef enum parserStatus_e {
    USTREAM_PROCESSING,
    USTREAM_FINISHED,
    USTREAM_FAULT = 0x6E00,
    USTREAM_FAULT_INPUT_COUNT = 0x6E01,
    USTREAM_FAULT_OUTPUT_COUNT = 0x6E02,
    USTREAM_FAULT_ECOUTPUT_COUNT = 0x6E03,
    USTREAM_FAULT_ADDRESS = 0x6E04,
    USTREAM_FAULT_PARSE = 0x6E05,
    USTREAM_FAULT_INTERNAL = 0x6E06,
    USTREAM_FAULT_VALUE = 0x6E07,
    USTREAM_FAULT_FEES = 0x6E08,

    USTREAM_FAULT_TXN_TO_LARGE = 0x6E09,
    USTREAM_FAULT_TOO_MANY_OUTPUTS = 0x6E10,
    USTREAM_FAULT_INVALID_ENTRY_COMMIT_LENGTH = 0x6E11,
    USTREAM_FAULT_INVALID_CHAIN_COMMIT_LENGTH = 0x6E12,

} parserStatus_e;

///**
// * @brief Decode an RLP encoded field - see
// * https://github.com/ethereum/wiki/wiki/RLP
// * @param [in] buffer buffer containing the RLP encoded field to decode
// * @param [in] bufferLength size of the buffer
// * @param [out] fieldLength length of the RLP encoded field
// * @param [out] offset offset to the beginning of the RLP encoded field from the
// * buffer
// * @param [out] list true if the field encodes a list, false if it encodes a
// * string
// * @return true if the RLP header is consistent
// */
//bool rlpDecodeLength(uint8_t *buffer, uint32_t bufferLength,
//                     uint32_t *fieldLength, uint32_t *offset, bool *list);

//bool rlpCanDecode(uint8_t *buffer, uint32_t bufferLength, bool *valid);

typedef enum {
    PUBLIC_OFFSET_FCT,
    PRIVATE_OFFSET_FCT,
    PUBLIC_OFFSET_EC,
    PRIVATE_OFFSEST_EC,
    PUBLIC_OFFSET_ID,
    PRIVATE_OFFSET_ID
}  keyType_t;

extern const uint32_t MAX_TXN_SIZE;

void sha256d(uint8_t *data, uint32_t len, uint8_t *out, uint32_t outlen);


void getRCDFromEd25519PublicKey(cx_ecfp_public_key_t *publicKey,
                      uint8_t *out, uint8_t len);

void getKeyFromEd25519PublicKey(cx_ecfp_public_key_t *publicKey,
                      uint8_t *out, uint8_t len);

void getFctAddressStringFromRCDHash(uint8_t *rcdhash,uint8_t *out, keyType_t keytype);

void getFctAddressStringFromKey(cx_ecfp_public_key_t *publicKey, uint8_t *out,
                                keyType_t fct_address_type);

bool adjustDecimals(char *src, uint32_t srcLength, char *target,
                    uint32_t targetLength, uint8_t decimals);


unsigned short fct_print_amount(uint64_t amount, int8_t *out,
                                uint32_t outlen);

uint64_t varint_decode(uint8_t *data, uint32_t len, uint8_t *bytes);

#endif

