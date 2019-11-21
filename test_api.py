#!/usr/bin/python3

import sys
import argparse
import requests
import time
import json

from utils import create_hmac_sig

URL_BASE = "http://localhost:5000/"

EXIT_NO_COMMAND = 1

def construct_parser():
    # construct argument parser
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="command")

    ## Account / Device creation

    parser_register = subparsers.add_parser("register", help="Register a claim code")
    parser_register.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_register.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_register.add_argument("token", metavar="TOKEN", type=str, help="the claim code token")

    parser_check = subparsers.add_parser("check", help="Check a claim code")
    parser_check.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_check.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_check.add_argument("token", metavar="TOKEN", type=str, help="the claim code token")

    parser_claim = subparsers.add_parser("claim", help="Claim a claim code")
    parser_claim.add_argument("token", metavar="TOKEN", type=str, help="the claim code token")
    parser_claim.add_argument("secret", metavar="SECRET", type=str, help="the claim code secret")
    parser_claim.add_argument("address", metavar="ADDR", type=str, help="the claim code address")

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
    r = req("register", {"token": args.token}, args.api_key_token, args.api_key_secret)
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
