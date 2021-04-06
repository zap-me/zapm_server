import datetime

import gevent
import requests

class AddressWatcher(gevent.Greenlet):

    addresses = {}

    def __init__(self, testnet=True):
        gevent.Greenlet.__init__(self)

        self.transfer_tx_callback = None
        self.testnet = testnet
        if testnet:
            self.url_base = "https://api-test.wavesplatform.com/v0"
            self.asset_id = "CgUrFtinLXEbJwJVjwwcppk4Vpz1nMmR3H5cQaDcUcfe"
        else:
            self.url_base = "https://api.wavesplatform.com/v0"
            self.asset_id = "9R3iLi4qGLVWKc16Tg98gmRvgg1usGEYd7SgC1W5D6HB"

    def start_watching(self, transfer_tx_callback):
        self.transfer_tx_callback = transfer_tx_callback
        self.start()

    def _run(self):
        print("running AddressWatcher...")
        dt = datetime.datetime.utcnow()
        js_datestring = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        after = None
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
                        if self.transfer_tx_callback:
                            self.transfer_tx_callback(api_keys, tx)
                if "lastCursor" in body:
                    after = body["lastCursor"]
            else:
                #TODO log error
                print(r)
            # sleep
            gevent.sleep(5)

    def watch(self, address, api_key):
        if not address in self.addresses:
            self.addresses[address] = api_keys = []
        else:
            api_keys = self.addresses[address]
        if api_key not in api_keys:
            api_keys.append(api_key)

    def watched(self):
        return self.addresses

    def transfer_tx(self, txid):
        url = self.url_base + "/transactions/transfer/" + txid
        r = requests.get(url)
        if r.status_code == 200:
            body = r.json()
            return body["data"]
        return None
