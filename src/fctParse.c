/*******************************************************************************
*   Ripple Wallet
*   (c) 2017 Ledger
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

#include "fctParse.h"

#define STI_UINT16 0x01
#define STI_UINT32 0x02
#define STI_AMOUNT 0x06
#define STI_VL 0x07
#define STI_ACCOUNT 0x08

#define FCTTX_HEADER_V2 0x02
#define FCTTX_INPUT 0x02
#define FCTTX_OUTPUT 0x02


#define FCT_UINT16_TRANSACTION_TYPE 0x02
#define FCT_UINT32_FLAGS 0x02
#define FCT_UINT32_SOURCE_TAG 0x03
#define FCT_UINT32_SEQUENCE 0x04
#define FCT_UINT32_LAST_LEDGER_SEQUENCE 0x1B
#define FCT_UINT32_DESTINATION_TAG 0x0E
#define FCT_AMOUNT_AMOUNT 0x01
#define FCT_AMOUNT_FEES 0x08
#define FCT_VL_SIGNING_PUB_KEY 0x03
#define FCT_ACCOUNT_ACCOUNT 0x01
#define FCT_ACCOUNT_DESTINATION 0x03

parserStatus_e parseTxAddress(uint8_t *data, uint32_t length, uint8_t *amtsz, 
		uint8_t count, txContentAddress_t *context, 
		uint32_t *offsetParam);
void parse_fct_amount(uint64_t *value, uint8_t *data) {
    *value = ((uint64_t)data[7]) | ((uint64_t)data[6] << 8) |
             ((uint64_t)data[5] << 16) | ((uint64_t)data[4] << 24) |
             ((uint64_t)data[3] << 32) | ((uint64_t)data[2] << 40) |
             ((uint64_t)data[1] << 48) | ((uint64_t)data[0] << 56);
    *value -= (uint64_t)0x4000000000000000;
}

void parse_uint32(uint32_t *value, uint8_t *data) {
    *value = ((uint32_t)data[3]) | ((uint32_t)data[2] << 8) |
             ((uint32_t)data[1] << 16) | ((uint32_t)data[0] << 24);
}

parserStatus_e processUint16(uint8_t *data, uint32_t length,
                             txContent_t *context, uint32_t *offsetParam) {
    parserStatus_e result = USTREAM_FAULT;
#if 0
    uint32_t offset = *offsetParam;
    uint8_t fieldId = data[offset] & 0x0f;
    if ((offset + 1 + 2) > length) {
        result = USTREAM_PROCESSING;
        goto error;
    }
    switch (fieldId) {
    case XRP_UINT16_TRANSACTION_TYPE:
        if ((data[offset + 1] != 0x00) || (data[offset + 2] != 0x00)) {
            goto error;
        }
        break;
    default:
        goto error;
    }
    *offsetParam = offset + 1 + 2;
    result = USTREAM_FINISHED;
error:
#endif
    return result;
}

parserStatus_e processUint32(uint8_t *data, uint32_t length,
                             txContent_t *context, uint32_t *offsetParam) {
    parserStatus_e result = USTREAM_FAULT;
#if 0
    uint32_t offset = *offsetParam;
    uint8_t fieldId = data[offset] & 0x0f;
    if ((offset + 1 + 4) > length) {
        result = USTREAM_PROCESSING;
        goto error;
    }
    switch (fieldId) {
    case 0: {
        uint8_t fieldId2 = data[offset + 1];
        if ((offset + 4) > length) {
            result = USTREAM_PROCESSING;
            goto error;
        }
        offset++;
        switch (fieldId2) {
        case XRP_UINT32_LAST_LEDGER_SEQUENCE:
            break;
        default:
            goto error;
        }
    }

    case XRP_UINT32_FLAGS:
        break;
    case XRP_UINT32_SEQUENCE:
        break;
    case XRP_UINT32_SOURCE_TAG:
        parse_uint32(&context->sourceTag, data + offset + 1);
        context->sourceTagPresent = 1;
        break;
    case XRP_UINT32_DESTINATION_TAG:
        parse_uint32(&context->destinationTag, data + offset + 1);
        context->destinationTagPresent = 1;
        break;
    default:
        goto error;
    }
    *offsetParam = offset + 1 + 4;
    result = USTREAM_FINISHED;
error:
#endif
    return result;
}


parserStatus_e parseTxV1(uint8_t *data, uint32_t length, 
		         uint8_t *amtsz, uint16_t amtszlen,
		         txContent_t *context,
                         uint32_t *offset) {

    parserStatus_e result = USTREAM_FAULT_PARSE;

    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }
    context->header.timestamp_ms = &data[*offset];
    *offset += 6;

    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }
    context->header.inputcount = &data[*offset];
    ++(*offset);

    if ( *context->header.inputcount > MAX_INPUT_ADDRESSES )
    {
        result = USTREAM_FAULT_INPUT_COUNT;
	goto error;
    } 
    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }
    context->header.outputcount = &data[*offset];
    ++(*offset);

    if ( *context->header.outputcount > MAX_OUTPUT_ADDRESSES )
    {
        result = USTREAM_FAULT_OUTPUT_COUNT;
        goto error;
    }
    if ( *offset > length )
    {
        result = USTREAM_PROCESSING;
        goto error;
    }
    context->header.ecpurchasecount = &data[*offset];
    ++(*offset);

    if ( *context->header.ecpurchasecount > MAX_ECOUTPUT_ADDRESSES )
    {
        result = USTREAM_FAULT_ECOUTPUT_COUNT;
        goto error;
    }

    result = parseTxAddress(data, length, &amtsz[0],
		            *context->header.inputcount, context->inputs, offset);
    if ( result != USTREAM_FINISHED )
    {
        goto error;
    }

    result = parseTxAddress(data, length, &amtsz[*context->header.inputcount], 
		            *context->header.outputcount, context->outputs, offset);
    if ( result != USTREAM_FINISHED )
    {
        goto error;
    }

    result = parseTxAddress(data, length, 
               &amtsz[*context->header.inputcount+*context->header.outputcount],
	       *context->header.ecpurchasecount, context->ecpurchase, offset);
    if ( result != USTREAM_FINISHED )
    {
        goto error;
    }

    result = USTREAM_FINISHED;

error:
    return result;
}

parserStatus_e parseTxAddress(uint8_t *data, uint32_t length, uint8_t *amtsz,
		              uint8_t count, txContentAddress_t *context, 
			      uint32_t *offsetParam)
{
    parserStatus_e result = USTREAM_FAULT_ADDRESS;
    uint32_t offset = *offsetParam;
    for (int i = 0 ; i < count; ++i )
    {
	uint8_t amtsize = *amtsz;
        if ( offset+amtsize > length )
        {
            goto error;
        }
        context[i].value = 0;
	for(int j = 0; j < *amtsz; --j,--amtsize)
	{
            context[i].value |= data[offset+j] >> 8 * amtsize;
	}
	++amtsz;
        offset += amtsize;
//        var checksum = sha256d(copyBuffer(add, 0, 34))
//        if (bufferToHex(copyBuffer(checksum, 0, 4)) === bufferToHex(copyBuffer(add, 34, 38))) {
//          return true
//        }

        if ( offset+32 > length )
        {
            goto error;
	}
        context[i].rcdhash =  &data[offset];
	offset+=32;
    }

    *offsetParam = offset;
    result = USTREAM_FINISHED;
error:
    return result;
}


parserStatus_e parseTxInternal(uint8_t *data, uint32_t length,
		               uint8_t *amtsz, uint16_t amtszlen,
                               txContent_t *context) {
    uint32_t offset = 0;
    parserStatus_e result = USTREAM_FAULT;
    //TODO: Send in the transaction data in small chunks from jswrapper 
    //(not to exceed 255 bytes for each chunk)

    //while (offset != length) {
        if (offset > length) {
            goto error;
        }
        uint8_t dataType = data[offset];
        switch (dataType) {
        case FCTTX_HEADER_V2:
	    offset += 1;
	    context->header.version = dataType;//&data[offset];
            result = parseTxV1(data, length, amtsz, amtszlen, context, &offset);
            break;
    /*    case STI_UINT32:
            result = processUint32(data, length, context, &offset);
            break;
        case STI_AMOUNT:
            result = processAmount(data, length, context, &offset);
            break;
        case STI_VL:
            result = processVl(data, length, context, &offset);
            break;
        case STI_ACCOUNT:
            result = processAccount(data, length, context, &offset);
            break;*/
        default:
            //result = USTREAM_FAULT_INTERNAL;
	    return 0x6E00|(uint8_t)dataType;
            goto error;
        }
        if (result != USTREAM_FINISHED) {
            goto error;
        }
   // }

error:
    return result;
}

void initContent(txContent_t *content)
{
    content->header.timestamp_ms = NULL;
    content->header.inputcount = NULL;
    content->header.outputcount = NULL;
    content->header.ecpurchasecount = NULL;

    for ( int i = 0; i < MAX_INPUT_ADDRESSES; ++i )
    {
        content->inputs[i].value = NULL;
	//content->inputs[i].vallen = 0;
        content->inputs[i].rcdhash = NULL;
    }


    for ( int i = 0; i < MAX_OUTPUT_ADDRESSES; ++i )
    {
        content->outputs[i].value = NULL;
	//content->outputs[i].vallen = 0;
        content->outputs[i].rcdhash = NULL;
    }
    for ( int i = 0; i < MAX_ECOUTPUT_ADDRESSES; ++i )
    {
        content->ecpurchase[i].value = NULL;
	//content->ecpurchase[i].vallen = 0;
        content->ecpurchase[i].rcdhash = NULL;
    }
}

parserStatus_e parseTx(uint8_t *data, uint32_t length, 
		       uint8_t *amtsz, uint16_t amtszlen, 
		       txContent_t *content) {
    parserStatus_e result = USTREAM_FAULT;
    initContent(content);
    result = parseTxInternal(data, length, amtsz, amtszlen, content);
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
