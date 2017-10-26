/*******************************************************************************
*   Ledger Blue
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

/**
 * @brief Utilities for Factom Hardware Wallet logic
 * @file fctUtils.h
 * @author MyFactomWallet Development Team 
 * @version 1.0
 * @date 25th of October 2017
 */

#include "os.h"
#include "cx.h"
#include <stdbool.h>
#include "fctUtils.h"
#include "btchip_base58.h"

bool rlpCanDecode(uint8_t *buffer, uint32_t bufferLength, bool *valid) {
    if (*buffer <= 0x7f) {
    } else if (*buffer <= 0xb7) {
    } else if (*buffer <= 0xbf) {
        if (bufferLength < (1 + (*buffer - 0xb7))) {
            return false;
        }
        if (*buffer > 0xbb) {
            *valid = false; // arbitrary 32 bits length limitation
            return true;
        }
    } else if (*buffer <= 0xf7) {
    } else {
        if (bufferLength < (1 + (*buffer - 0xf7))) {
            return false;
        }
        if (*buffer > 0xfb) {
            *valid = false; // arbitrary 32 bits length limitation
            return true;
        }
    }
    *valid = true;
    return true;
}

bool rlpDecodeLength(uint8_t *buffer, uint32_t bufferLength,
                     uint32_t *fieldLength, uint32_t *offset, bool *list) {
    if (*buffer <= 0x7f) {
        *offset = 0;
        *fieldLength = 1;
        *list = false;
    } else if (*buffer <= 0xb7) {
        *offset = 1;
        *fieldLength = *buffer - 0x80;
        *list = false;
    } else if (*buffer <= 0xbf) {
        *offset = 1 + (*buffer - 0xb7);
        *list = false;
        switch (*buffer) {
        case 0xb8:
            *fieldLength = *(buffer + 1);
            break;
        case 0xb9:
            *fieldLength = (*(buffer + 1) << 8) + *(buffer + 2);
            break;
        case 0xba:
            *fieldLength =
                (*(buffer + 1) << 16) + (*(buffer + 2) << 8) + *(buffer + 3);
            break;
        case 0xbb:
            *fieldLength = (*(buffer + 1) << 24) + (*(buffer + 2) << 16) +
                           (*(buffer + 3) << 8) + *(buffer + 4);
            break;
        default:
            return false; // arbitrary 32 bits length limitation
        }
    } else if (*buffer <= 0xf7) {
        *offset = 1;
        *fieldLength = *buffer - 0xc0;
        *list = true;
    } else {
        *offset = 1 + (*buffer - 0xf7);
        *list = true;
        switch (*buffer) {
        case 0xf8:
            *fieldLength = *(buffer + 1);
            break;
        case 0xf9:
            *fieldLength = (*(buffer + 1) << 8) + *(buffer + 2);
            break;
        case 0xfa:
            *fieldLength =
                (*(buffer + 1) << 16) + (*(buffer + 2) << 8) + *(buffer + 3);
            break;
        case 0xfb:
            *fieldLength = (*(buffer + 1) << 24) + (*(buffer + 2) << 16) +
                           (*(buffer + 3) << 8) + *(buffer + 4);
            break;
        default:
            return false; // arbitrary 32 bits length limitation
        }
    }

    return true;
}

void getFctAddressFromKey(cx_ecfp_public_key_t *publicKey, uint8_t *out,
                          cx_sha3_t *sha3Context) {
    uint8_t hashAddress[32];
    cx_keccak_init(sha3Context, 256);
    cx_hash((cx_hash_t *)sha3Context, CX_LAST, publicKey->W + 1, 64,
            hashAddress);
    os_memmove(out, hashAddress + 12, 20);
}


static const uint8_t const HEXDIGITS[] = "0123456789abcdef";

static const uint8_t const MASK[] = {0x80, 0x40, 0x20, 0x10,
                                     0x08, 0x04, 0x02, 0x01};

char convertDigit(uint8_t *address, uint8_t index, uint8_t *hash) {
    unsigned char digit = address[index / 2];
    if ((index % 2) == 0) {
        digit = (digit >> 4) & 0x0f;
    } else {
        digit = digit & 0x0f;
    }
    if (digit < 10) {
        return HEXDIGITS[digit];
    } else {
        unsigned char data = hash[index / 8];
        if (((data & MASK[index % 8]) != 0) && (digit > 9)) {
            return HEXDIGITS[digit] /*- 'a' + 'A'*/;
        } else {
            return HEXDIGITS[digit];
        }
     }
}
void sha256d(uint8_t *data, uint32_t len, uint8_t *out)
{
    uint8_t in[32];
    cx_hash_sha256(data,len,in);
    cx_hash_sha256(in,32,out);
}


void getRCDFromEd25519PublicKey(cx_ecfp_public_key_t *publicKey,
	                      uint8_t *out, uint8_t len, uint8_t keytype)
{
    if ( len < 33 )
    {
        THROW(0x60ED);
    }
    if (publicKey->curve == CX_CURVE_Ed25519 && publicKey->W[0] != 0xED) 
    {
	int offset = 0;
	if ( keytype == PUBLIC_OFFSET_FCT )
	{
            out[0] = 0x01;//RCD key type 1
	    offset = 1;
	}
        for (uint8_t i = 0; i < 32; i++) 
	{
            out[i + offset] = publicKey->W[64 - i];
	}
        if ((publicKey->W[32] & 1) != 0) 
	{
            out[31 + offset] |= 0x80;
        }
    }
}

//the key prefix code is byte swapped
const uint16_t g_factom_key_prefix[] = { 0xb15f, 0x7864, 0x2a59, 0xb65d };

void getFctAddressStringFromKey(cx_ecfp_public_key_t *publicKey, uint8_t *out,
                                uint8_t keytype) {
    uint8_t address[38];//prefix(2 bytes) + RCD_hash(32 bytes) + checksum(4 bytes)
    uint8_t checksum[32];

    //https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md
    
    //1) Concatenate 0x5fb1 and the RCD Hash bytewise
    *(uint16_t*)address = g_factom_key_prefix[keytype];
    sha256d(publicKey->W, publicKey->W_len, &address[2]);
    
    //2) Take the SHA256d of the above data. Append the first 4 bytes of 
    //   this SHA256d to the end of the above value bytewise
    sha256d(address, 34, checksum);

    os_memmove(address+34, checksum, 4);

    //3) Convert the above value from base 256 to base 58. Use standard 
    //   Bitcoin base58 encoding to display the number
    btchip_encode_base58(address, 38, out, 52);
}

bool adjustDecimals(char *src, uint32_t srcLength, char *target,
                    uint32_t targetLength, uint8_t decimals) {
    uint32_t startOffset;
    uint32_t lastZeroOffset = 0;
    uint32_t offset = 0;
    if ((srcLength == 1) && (*src == '0')) {
        if (targetLength < 2) {
            return false;
        }
        target[0] = '0';
        target[1] = '\0';
        return true;
    }
    if (srcLength <= decimals) {
        uint32_t delta = decimals - srcLength;
        if (targetLength < srcLength + 1 + 2 + delta) {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '.';
        for (uint32_t i = 0; i < delta; i++) {
            target[offset++] = '0';
        }
        startOffset = offset;
        for (uint32_t i = 0; i < srcLength; i++) {
            target[offset++] = src[i];
        }
        target[offset] = '\0';
    } else {
        uint32_t sourceOffset = 0;
        uint32_t delta = srcLength - decimals;
        if (targetLength < srcLength + 1 + 1) {
            return false;
        }
        while (offset < delta) {
            target[offset++] = src[sourceOffset++];
        }
        if (decimals != 0) {
            target[offset++] = '.';
        }
        startOffset = offset;
        while (sourceOffset < srcLength) {
            target[offset++] = src[sourceOffset++];
        }
	target[offset] = '\0';
    }
    for (uint32_t i = startOffset; i < offset; i++) {
        if (target[i] == '0') {
            if (lastZeroOffset == 0) {
                lastZeroOffset = i;
            }
        } else {
            lastZeroOffset = 0;
        }
    }
    if (lastZeroOffset != 0) {
        target[lastZeroOffset] = '\0';
        if (target[lastZeroOffset - 1] == '.') {
            target[lastZeroOffset - 1] = '\0';
        }
    }
    return true;
}
