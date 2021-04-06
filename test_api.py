#!/usr/bin/python3

import sys
import argparse
import time
import json

import requests
import socketio

from utils import create_hmac_sig

URL_BASE = "http://localhost:5000/"
WS_URL = "ws://localhost:5000/"

EXIT_NO_COMMAND = 1

def construct_parser():
    # construct argument parser
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="command")

    ## Websocket

    parser_ws = subparsers.add_parser("websocket", help="Listen to a websocket")
    parser_ws.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_ws.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")

    ## REST commands

    parser_watch = subparsers.add_parser("watch", help="Watch an address")
    parser_watch.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_watch.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_watch.add_argument("address", metavar="ADDR", type=str, help="the address to watch")

    parser_register = subparsers.add_parser("register", help="Register a claim code")
    parser_register.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_register.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_register.add_argument("token", metavar="TOKEN", type=str, help="the claim code token")
    parser_register.add_argument("amount", metavar="AMOUNT", type=int, help="the claim code amount (integer, lowest denomination of asset)")

    parser_check = subparsers.add_parser("check", help="Check a claim code")
    parser_check.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_check.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_check.add_argument("token", metavar="TOKEN", type=str, help="the claim code token")

    parser_claim = subparsers.add_parser("claim", help="Claim a claim code")
    parser_claim.add_argument("token", metavar="TOKEN", type=str, help="the claim code token")
    parser_claim.add_argument("secret", metavar="SECRET", type=str, help="the claim code secret")
    parser_claim.add_argument("address", metavar="ADDR", type=str, help="the claim code address")

    parser_merchanttx = subparsers.add_parser("merchanttx", help="Update merchant tx table")
    parser_merchanttx.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_merchanttx.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")

    parser_wallet_address = subparsers.add_parser("wallet_address", help="Set the user wallet address")
    parser_wallet_address.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_wallet_address.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_wallet_address.add_argument("wallet_address", metavar="WALLET_ADDRESS", type=str, help="the wallet address")

    parser_rates = subparsers.add_parser("rates", help="Get the rates")
    parser_rates.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_rates.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")

    parser_banks = subparsers.add_parser("banks", help="Get the bank accounts for the user")
    parser_banks.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_banks.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")

    parser_settlement = subparsers.add_parser("settlement", help="Create a settlement")
    parser_settlement.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_settlement.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_settlement.add_argument("bank_token", metavar="BANK_TOKEN", type=int, help="the token of the bank account to settle to")
    parser_settlement.add_argument("amount", metavar="AMOUNT", type=int, help="the zap settlement amount (integer, lowest denomination of asset)")

    parser_settlement_set_txid = subparsers.add_parser("settlement_set_txid", help="Update a settlement with a txid")
    parser_settlement_set_txid.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_settlement_set_txid.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_settlement_set_txid.add_argument("token", metavar="TOKEN", type=str, help="Settlement token")
    parser_settlement_set_txid.add_argument("txid", metavar="TXID", type=str, help="Settlement transaction ID")

    return parser

def req(endpoint, params=None, api_key_token=None, api_key_secret=None):
    if api_key_token:
        if not params:
            params = {}
        params["nonce"] = int(time.time())
        params["api_key"] = api_key_token
    url = URL_BASE + endpoint
    if params:
        headers = {"Content-type": "application/json"}
        body = json.dumps(params)
        if api_key_token:
            headers["X-Signature"] = create_hmac_sig(api_key_secret, body)
        print("   POST - " + url)
        r = requests.post(url, headers=headers, data=body)
    else:
        print("   GET - " + url)
        r = requests.get(url)
    return r

def check_request_status(request):
    try:
        request.raise_for_status()
    except Exception as e:
        print("::ERROR::")
        print(str(request.status_code) + " - " + request.url)
        print(request.text)
        raise e

def websocket(args):
    # pylint: disable=unused-variable
    # pylint: disable=invalid-name

    print(":: calling websocket..")
    # create auth data
    nonce = int(time.time())
    sig = create_hmac_sig(args.api_key_secret, str(nonce))
    auth = {"signature": sig, "api_key": args.api_key_token, "nonce": nonce}
    # open websocket
    sio = socketio.Client()
    @sio.event
    def connect():
        print("connection established")
        sio.emit("auth", auth)

    @sio.event
    def info(data):
        print("info event received:", data)

    @sio.event
    def claimed(data):
        print("claimed event received:", data)

    @sio.event
    def tx(data):
        print("tx event received:", data)

    @sio.event
    def disconnect():
        print("disconnected from server")

    sio.connect(WS_URL)
    sio.wait()

def watch(args):
    print(":: calling watch..")
    r = req("watch", {"address": args.address}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def register(args):
    print(":: calling register..")
    r = req("register", {"token": args.token, "amount": args.amount}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def check(args):
    print(":: calling check..")
    r = req("check", {"token": args.token}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def claim(args):
    print(":: calling claim..")
    r = req("claim", {"token": args.token, "secret": args.secret, "address": args.address})
    check_request_status(r)
    print(r.text)

def merchanttx(args):
    print(":: calling merchanttx..")
    r = req("merchanttx", {}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def rates(args):
    print(":: calling rates..")
    r = req("rates", {}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def wallet_address(args):
    print(":: calling wallet_address..")
    r = req("wallet_address", {"address": args.wallet_address}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def banks(args):
    print(":: calling banks..")
    r = req("banks", {}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def settlement(args):
    print(":: calling settlement..")
    r = req("settlement", {"bank": args.bank_token, "amount": args.amount}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def settlement_set_txid(args):
    print(":: calling settlement_set_txid..")
    r = req("settlement_set_txid", {"token": args.token, "txid": args.txid}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def run():
    # parse arguments
    parser = construct_parser()
    args = parser.parse_args()

    # set appropriate function
    function = None
    if args.command == "websocket":
        function = websocket
    elif args.command == "watch":
        function = watch
    elif args.command == "register":
        function = register
    elif args.command == "check":
        function = check
    elif args.command == "claim":
        function = claim
    elif args.command == "merchanttx":
        function = merchanttx
    elif args.command == "rates":
        function = rates
    elif args.command == "wallet_address":
        function = wallet_address
    elif args.command == "banks":
        function = banks
    elif args.command == "settlement":
        function = settlement
    elif args.command == "settlement_set_txid":
        function = settlement_set_txid
    else:
        parser.print_help()
        sys.exit(EXIT_NO_COMMAND)

    if function:
        function(args)

if __name__ == "__main__":
    run()
