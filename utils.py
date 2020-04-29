import os
import binascii
import hmac
import hashlib
import base64
import io

import requests
import base58
from flask import make_response
from stdnum.nz import bankaccount
import bnz_ib4b

def generate_key(num=20):
    return binascii.hexlify(os.urandom(num)).decode()

def to_bytes(data):
    if not isinstance(data, (bytes, bytearray)):
        return data.encode("utf-8")
    return data

def create_hmac_sig(api_secret, message):
    _hmac = hmac.new(to_bytes(api_secret), msg=to_bytes(message), digestmod=hashlib.sha256)
    signature = _hmac.digest()
    signature = base64.b64encode(signature).decode("utf-8")
    return signature

def check_hmac_auth(api_key, nonce, sig, body):
    if nonce <= api_key.nonce:
        return False, "old nonce"
    our_sig = create_hmac_sig(api_key.secret, body)
    if sig == our_sig:
        api_key.nonce = nonce
        return True, ""
    return False, "invalid signature"

def bankaccount_is_valid(account):
    return bankaccount.is_valid(account)

def ib4b_response(filename, settlements, sender_name, sender_bank_account):
    # create output 
    output = io.StringIO()
    # process settlements
    txs = []
    for settlement in settlements:
        bank_account = settlement.bank.account_number.replace('-', '')
        tx = (bank_account, settlement.amount_receive, "zap settlement", settlement.token, settlement.user.merchant_code, "zap settlement", settlement.token)
        txs.append(tx)
    sender_bank_account = sender_bank_account.replace('-', '')
    bnz_ib4b.write_txs(output, "", sender_bank_account, sender_name, txs)
    # return file response
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = "application/octet-stream"
    resp.headers['Content-Disposition'] = "inline; filename=%s" % filename
    return resp

def blockchain_transactions(node, wallet_address, limit, after=None):
    url = '%s/transactions/address/%s/limit/%s' % (node, wallet_address, limit)
    if after:
        url += '?after=%s' % after
    print(':: requesting %s..' % url)
    r = requests.get(url)
    if r.status_code != 200:
        print('ERROR: status code is %d' % r.status_code)
    txs = r.json()[0]
    print(':: retrieved %d records' % len(txs))
    txs_result = []
    for tx in txs:
        if 'attachment' in tx:
            attachment = tx['attachment']
            if attachment:
                tx['attachment'] = base58.b58decode(attachment).decode('utf-8')
        if 'recipient' in tx:
            tx['direction'] = tx['recipient'] == wallet_address and tx['sender'] != wallet_address
        else:
            tx['direction'] = False
        txs_result.append(tx)
    return txs_result
