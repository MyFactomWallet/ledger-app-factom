
if (typeof ledger == 'undefined') {
    ledger = require('../src');
    comm = ledger.comm_node;
    browser = false;
}
else {
    browser = true;
    comm = ledger.comm_u2f;
}

var Q = require('q');

var TIMEOUT = 200;

var tests = [
    {name: 'testFctGetAddress', run: require('./FctGetPublicAddress')},
    {
        run: function () {
            var deferred = Q.defer();
            var s = 1;
            console.info('You have ' + s + ' seconds to switch to MyFactomWallet app ...');
            var interval = setInterval(function () {
                if (--s) {
                    console.log(s + ' ...');
                } else {
                    clearInterval(interval);
                    deferred.resolve();
                }
            }, 1000);
            return deferred.promise;
        }
    },
    {name: 'testFctGetAddress', run: require('./FctGetPublicAddress')},
    {name: 'testFctGetAddress', run: require('./FctDisplayPublicAddress')},
    {name: 'testFctGetAddress', run: require('./FctSignTransaction')},
];

function runTests() {
    tests.reduce(function (a, step) {
        return a.then(function () {
            console.info(step.name ? 'Running test ' + step.name : '');
            return (step.run)(comm, ledger, TIMEOUT);
        }).fail(function (err) {
            console.error('Failed test', step.name, err);
        })
    }, Q.resolve());
}

if (!browser) {
    runTests();
}

module.exports = runTests;
