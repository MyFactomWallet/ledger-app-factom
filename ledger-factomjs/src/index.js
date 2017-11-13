/********************************************************************************
*   Ledger Node JS API for Factom
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


var isNode = (typeof window === 'undefined');

var ledger = module.exports;

if (isNode) {
	ledger.comm_node = require('ledgerco/src/ledger-comm-node');
}
else ledger.comm_u2f = require('ledgerco/src/ledger-comm-u2f');

ledger.factom = require('./ledger-factom');

module.exports = ledger;

