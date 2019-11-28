import datetime

import gevent
import requests

class AddressWatcher(gevent.Greenlet):

    addresses = {}

    def __init__(self, transfer_tx_callback, testnet=True):
        gevent.Greenlet.__init__(self)

        self.transfer_tx_callback = transfer_tx_callback
        self.testnet = testnet
        if testnet:
            self.url_base = "https://api-test.wavesplatform.com/v0"
            self.asset_id = "CgUrFtinLXEbJwJVjwwcppk4Vpz1nMmR3H5cQaDcUcfe"
        else:
            self.url_base = "https://api.wavesplatform.com/v0"
            self.asset_id = "9R3iLi4qGLVWKc16Tg98gmRvgg1usGEYd7SgC1W5D6HB"

    def _run(self):
        print("running AddressWatcher...")
        dt = datetime.datetime.utcnow()
        js_datestring = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        after = None
        last = True
        while 1:
            # poll for more transactions
            url = self.url_base + "/transactions/transfer"
            params = {"assetId": self.asset_id, "timeStart": js_datestring, "sort": "asc"}
            if after:
                params["after"] = after
            #print(params)
            r = requests.get(url, params=params)
            if r.status_code == 200:
                body = r.json()
                for tx in body["data"]:
                    tx = tx["data"]
                    if tx["recipient"] in self.addresses:
                        api_keys = self.addresses[tx["recipient"]]
                        self.transfer_tx_callback(api_keys, tx)
                if "lastCursor" in body:
                    after = body["lastCursor"]
                if "isLastPage" in body:
                    last = body["isLastPage"]
            else:
                #TODO log error
                print(r)
            # sleep
            gevent.sleep(10)

    def watch(self, address, api_key):
        if not address in self.addresses:
            self.addresses[address] = api_keys = [] 
        else:
            api_keys = self.addresses[address]
        if api_key not in api_keys:
            api_keys.append(api_key)

    def watched(self):
        return self.addresses
