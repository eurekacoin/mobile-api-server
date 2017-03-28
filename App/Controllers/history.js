let logger = require('log4js').getLogger('History Controller'),
    InsightApi = require("../Services/InsightApi"),
	async = require('async');


class HistoryController {

	constructor() {
        logger.info('Init');
	}
	
	getAddressHistoryList(cb, data) {
        var req = data.req,
            options = this._formatOptions(req.params.limit, req.params.offset),
            addresses = data._get.addresses && Array.isArray(data._get.addresses) ? data._get.addresses : [];

        if (addresses.length) {

            InsightApi.getAddressesHistory(addresses, options, (error, body) => {
                return cb(error, this._formatHistory(body));
            });

        } else {
            return cb(null, []);
        }

	}
	
	getAddressHistory(cb, data) {
	    var req = data.req,
            options = this._formatOptions(req.params.limit, req.params.offset);


	    InsightApi.getAddressesHistory([data._get.address], options, (error, body) => {
            return cb(error, this._formatHistory(body));
        });

	}

	_formatOptions(limit, offset) {

	    var MAX_LIMIT = 50;

        limit = parseInt(limit, 10);
        offset = parseInt(offset, 10);

        if (isNaN(limit)) {
            limit = MAX_LIMIT;
        }

        if (isNaN(offset)) {
            offset = 0
        }

        limit = Math.abs(limit);
        offset = Math.abs(offset);

        if (limit > MAX_LIMIT) {
            limit = MAX_LIMIT;
        }

        return {
            from: offset,
            to: offset + limit
        };
    }

    _formatHistory(history) {

        var items = [];

        if (history && history.items && history.items.length) {
            history.items.forEach(function (item) {
                var from_address = [],
                    to_address = [],
                    vout = [];

                item.vin.forEach(function (vIn) {
                    if (to_address.indexOf(vIn.addr) === -1) {
                        to_address.push(vIn.addr);
                    }

                });

                item.vout.forEach(function (vOut) {

                    if (vOut.scriptPubKey && vOut.scriptPubKey.addresses) {

                        vOut.scriptPubKey.addresses.forEach(function (addr) {

                            if (from_address.indexOf(addr) === -1) {
                                from_address.push(addr)
                            }

                        });

                        vout.push({
                            value: vOut.value,
                            scriptPubKey: {
                                addresses: vOut.scriptPubKey.addresses
                            }
                        })
                    }


                });

                items.push({
                    block_time: item.blocktime ? item.blocktime : null,
                    block_height: item.blockheight ? item.blockheight : null,
                    block_hash: item.blockhash ? item.blockhash : null,
                    tx_hash: item.txid,
                    amount: item.valueIn,
                    from_address: from_address,
                    to_address: to_address,
                    vout: vout
                });
            });
        }



        return items;
    }

}

module.exports = HistoryController;

