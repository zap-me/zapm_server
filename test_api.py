#!/usr/bin/python3

import sys
import argparse
import requests
import time
import hmac
import hashlib
import base64
import json

URL_BASE = "http://localhost:5000/"

EXIT_NO_COMMAND = 1

def construct_parser():
    # construct argument parser
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="command")

    ## Account / Device creation

    parser_register = subparsers.add_parser("register", help="Register a claim code")
    parser_register.add_argument("token", metavar="TOKEN", type=str, help="the claim code token")

    parser_check = subparsers.add_parser("check", help="Check a claim code")
    parser_check.add_argument("token", metavar="TOKEN", type=str, help="the claim code token")

    parser_claim = subparsers.add_parser("claim", help="Claim a claim code")
    parser_claim.add_argument("token", metavar="TOKEN", type=str, help="the claim code token")
    parser_claim.add_argument("secret", metavar="SECRET", type=str, help="the claim code secret")
    parser_claim.add_argument("address", metavar="ADDR", type=str, help="the claim code address")

    return parser

def create_sig(device_key, device_secret, message):
    _hmac = hmac.new(device_secret.encode("latin-1"), msg=message.encode("latin-1"), digestmod=hashlib.sha256)
    signature = _hmac.digest()
    signature = base64.b64encode(signature).decode("utf-8")
    return signature

def req(endpoint, params=None, device_key=None, device_secret=None):
    if device_key:
        if not params:
            params = {}
        params["nonce"] = int(time.time())
        params["key"] = device_key
    url = URL_BASE + endpoint
    if params:
        headers = {"Content-type": "application/json"}
        body = json.dumps(params)
        if device_key:
            headers["X-Signature"] = create_sig(device_key, device_secret, body)
        print("   POST - " + url)
        r = requests.post(url, headers=headers, data=body)
    else:
        print("   GET - " + url)
        r = requests.get(url)
    return r

def check_request_status(r):
    try:
        r.raise_for_status()
    except Exception as e:
        print("::ERROR::")
        print(str(r.status_code) + " - " + r.url)
        print(r.text)
        raise e

def register(args):
    print(":: calling register..")
    r = req("request", {"token": args.token})
    check_request_status(r)
    print(r.text)

def check(args):
    print(":: calling check..")
    r = req("status", {"token": args.token})
    check_request_status(r)
    print(r.text)

def claim(args):
    print(":: calling claim..")
    r = req("status", {"token": args.token, "secret": args.secret, "address": args.address})
    check_request_status(r)
    print(r.text)

if __name__ == "__main__":
    # parse arguments
    parser = construct_parser()
    args = parser.parse_args()

    # set appropriate function
    function = None
    if args.command == "register":
        function = register
    elif args.command == "check":
        function = check
    elif args.command == "claim":
        function = claim
    else:
        parser.print_help()
        sys.exit(EXIT_NO_COMMAND)

    if function:
        function(args)
