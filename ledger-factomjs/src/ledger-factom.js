/********************************************************************************
*   Ledger Node JS API
*   (c) 2016-2017 Ledger
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

'use strict';

var Q = require('q')
var utils = require('ledgerco/src/utils')
var fctUtil = require('factomjs-util')

var LedgerFct = function(comm) {
	this.comm = comm;
	this.comm.setScrambleKey('mFw');

	//need to clamp the minimum timeout to allow ample time for ledger to respond
	if ( this.comm.timeout < 200 ) {
          this.comm.timeout = 200;
	}

	//console.log(comm)
}

LedgerFct.prototype.getAddress_async = function(path, boolDisplay, boolChaincode) {
	var splitPath = utils.splitPath(path);
	var buffer = new Buffer(5 + 1 + splitPath.length * 4);
	buffer[0] = 0xe0;
	buffer[1] = 0x02;
	buffer[2] = (boolDisplay ? 0x01 : 0x00);
	buffer[3] = (boolChaincode ? 0x01 : 0x00);
	buffer[4] = 1 + splitPath.length * 4;
	buffer[5] = splitPath.length;
	splitPath.forEach(function (element, index) {
		buffer.writeUInt32BE(element, 6 + 4 * index);
	});
	return this.comm.exchange(buffer.toString('hex'), [0x9000]).then(function(response) {
		var result = {};
		var response = new Buffer(response, 'hex');
		var publicKeyLength = response[0];
		var addressLength = response[1 + publicKeyLength];
		result['publicKey'] = response.slice(1, 1 + publicKeyLength).toString('hex');
		result['address'] = response.slice(1 + publicKeyLength + 1, 1 + publicKeyLength + 1 + addressLength).toString('ascii');
		if (boolChaincode) {
			result['chainCode'] = response.slice(1 + publicKeyLength + 1 + addressLength, 1 + publicKeyLength + 1 + addressLength + 32).toString('hex');
		}
		return result;
	});
}

LedgerFct.prototype.signTransaction_async = function(path, tx) {
	var splitPath = utils.splitPath(path);
	var offset = 0;
	var rawTx = tx.MarshalBinarySig()//new Buffer(rawTxHex, 'hex');
	var apdus = [];
	var response = [];
	var self = this;	
	//send chunks accross to device.  
	//Need to be aware there is a max transaction size limit 
	//set within the device (20490 bytes) 
	//call split transaction to break down tx into chunks
        var amtsz = new Buffer(tx.Inputs.length + 
		               tx.Outputs.length + 
	                       tx.ECOutputs.length)	
	for (var i = 0; i < tx.Inputs.length; ++i) {
            var buf = fctUtil.intToBuffer(tx.Inputs[i])
            amtsz[i] = buf.length % 0x10 + 1
	}
	for ( i = 0; i < tx.Outputs.length; ++i) {
            var buf = fctUtil.intToBuffer(tx.Outputs[i])
            amtsz[i+tx.Inputs.length] = buf.length % 0x10 + 1
	}
	for ( i = 0; i < tx.ECOutputs.length; ++i) {
            var buf = fctUtil.intToBuffer(tx.ECOutputs[i])
            amtsz[i+tx.Inputs.length+tx.Outputs.length] = buf.length % 0x10 + 1
	}

	console.log('===============TXLENGTH==============')
	console.log(amtsz.toString('hex'))
	console.log('===============TXLENGTH==============')
	while (offset != rawTx.length ) {
		var maxChunkSize = (offset == 0 ? (150 - 1 - splitPath.length * 4) : 150)
		var chunkSize = (offset + maxChunkSize > rawTx.length ? rawTx.length - offset : maxChunkSize);
		var buffer = new Buffer(offset == 0 ? 5 + 1 + 2 + splitPath.length * 4 + chunkSize : 5 + chunkSize);
		buffer[0] = 0xe0;
		buffer[1] = 0x04;
		buffer[2] = (offset == 0 ? 0x00 : 0x80);
		buffer[3] = 0x00;
		if (offset == 0) {
		        buffer[4] = 1 + splitPath.length * 4 + chunkSize + 2;
			buffer[5] = splitPath.length;
			buffer.writeUInt16BE(rawTx.length, 6);
			splitPath.forEach(function (element, index) {
				buffer.writeUInt32BE(element, 6 + 4 * index + 2);
			});
		
			rawTx.copy(buffer, 6 + 4 * splitPath.length + 2, offset, offset + chunkSize );
		}
		else {
		        buffer[4] = chunkSize;
			rawTx.copy(buffer, 5, offset, offset + chunkSize);
		}
		apdus.push(buffer.toString('hex'));
		offset += chunkSize;
	}
	while (offset != amtsz.length ) {
                var maxChunkSize = 150
                var chunkSize = (offset + maxChunkSize > amtsz.length ? amtsz.length - offset : maxChunkSize);
                var buffer = new Buffer(chunkSize);
                buffer[0] = 0xe0;
                buffer[1] = 0x04;
                buffer[2] = 0x8F;
                buffer[3] = 0x00;
                buffer[4] = chunkSize;
                amtsz.copy(buffer, 5, offset, offset + chunkSize);
                apdus.push(buffer.toString('hex'));
                offset += chunkSize;
	}
	return utils.foreach(apdus, function(apdu) {
		return self.comm.exchange(apdu, [0x9000]).then(function(apduResponse) {
			response = apduResponse;
		})
	}).then(function() {		
		response = new Buffer(response, 'hex');
		var result = {};					
		result['v'] = response.slice(0, 1).toString('hex');
		result['r'] = response.slice(1, 1 + 32).toString('hex');
		result['s'] = response.slice(1 + 32, 1 + 32 + 32).toString('hex');
		return result;
	})
}

LedgerFct.prototype.getAppConfiguration_async = function() {
	var buffer = new Buffer(5);
	buffer[0] = 0xe0;
	buffer[1] = 0x06;
	buffer[2] = 0x00;
	buffer[3] = 0x00;
	buffer[4] = 0x00;
	return this.comm.exchange(buffer.toString('hex'), [0x9000]).then(function(response) {
			var result = {};
			var response = new Buffer(response, 'hex');
			result['arbitraryDataEnabled'] = (response[0] & 0x01);
			result['version'] = "" + response[1] + '.' + response[2] + '.' + response[3];
			return result;
	});
}

LedgerFct.prototype.close_async = function () {
	return this.comm.close_async().then(function() { return; } )
}


module.exports = LedgerFct;
