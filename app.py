#!/usr/bin/python3
import os
import logging
import sys
import json
import time
import requests

from flask import url_for, redirect, render_template, request, abort, jsonify
from flask_security.utils import encrypt_password
from flask_socketio import Namespace, emit, join_room, leave_room
from flask_security import current_user

from app_core import app, db, socketio, aw
from models import security, user_datastore, Role, User, Bank, ClaimCode, TxNotification, ApiKey, MerchantTx, Settlement
import admin
from utils import check_hmac_auth, generate_key, apply_merchant_rate
import bnz_ib4b

logger = logging.getLogger(__name__)
ws_api_keys = {}
ws_sids = {}
wallet_balances = {}

#
# Helper functions
#

def setup_logging(level):
    # setup logging
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter("[%(name)s %(levelname)s] %(message)s"))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

def add_user(email, password):
    with app.app_context():
        user = User.from_email(db.session, email)
        if user:
            #logger.error("user already exists")
            #return
            user.password = encrypt_password(password)
        else:
            user = user_datastore.create_user(email=email, password=encrypt_password(password))
        db.session.commit()

def create_role(name, desc):
    role = Role.from_name(db.session, name)
    if not role:
        role = Role(name=name, description=desc)
    else:
        role.description = desc
    db.session.add(role)
    return role

def add_role(email, role_name):
    with app.app_context():
        user = User.from_email(db.session, email)
        if not user:
            logger.error("user does not exist")
            return
        role = create_role(role_name, None)
        if role not in user.roles:
            user.roles.append(role)
        else:
            logger.info("user already has role")
        db.session.commit()

def add_merchant_codes():
    with app.app_context():
        for user in User.all(db.session):
            if not user.merchant_code:
                user.merchant_code = generate_key(4)
                db.session.add(user)
        db.session.commit()

def check_auth(api_key_token, nonce, sig, body):
    api_key = ApiKey.from_token(db.session, api_key_token)
    if not api_key:
        return False, "not found", None
    if not api_key.user.active:
        return False, "inactive account", None
    res, reason = check_hmac_auth(api_key, nonce, sig, body)
    if not res:
        return False, reason, None
    # update api key nonce
    db.session.commit()
    return True, "", api_key

def transfer_tx_callback(api_keys, tx):
    txt = json.dumps(tx)
    print("transfer_tx_callback: tx %s" % txt)
    for api_key in api_keys:
        print("sending 'tx' event to room %s" % api_key)
        socketio.emit("tx", txt, json=True, room=api_key)
        if not TxNotification.exists(db.session, tx["id"]):
            print("adding to tx notification table")
            api_key = ApiKey.from_token(db.session, api_key)
            txnoti = TxNotification(api_key.user, tx["id"])
            db.session.add(txnoti)
            db.session.commit()

def get_balance(wallet_address):
    url = '%s/assets/balance/%s/%s' % (app.config["NODE_ADDRESS"], wallet_address, app.config["ASSET_ID"])
    print(':: getting balance - %s' % url)
    r = requests.get(url)
    print(':: balance request status - %d' % r.status_code)
    if r.status_code == 200:
        balance = r.json()['balance'] / 100
        return balance
    return -1

# get the wallet balance, or update/create it if it does not exist or has expired
def get_update_balance(wallet_address):
    now = time.time()
    if wallet_address in wallet_balances:
        timestamp, balance = wallet_balances[wallet_address]
        # check if balance has expired
        if now - timestamp > 60 * 10:
            # update balance and timestamp
            balance = get_balance(wallet_address)
            wallet_balances[wallet_address] = (now, balance)
            # return new balance
            return balance
        else:
            # return cached balance
            return balance
    else:
        # initial balance and timestamp
        balance = get_balance(wallet_address)
        wallet_balances[wallet_address] = (now, balance)
        # return initial balance
        return balance

@app.before_first_request
def start_address_watcher():
    aw.transfer_tx_callback = transfer_tx_callback
    aw.start()

def bad_request(message):
    response = jsonify({"message": message})
    response.status_code = 400
    return response

#
# Flask views
#

@app.context_processor
def inject_rates():
    return dict(sales_tax=app.config["SALES_TAX"], settlement_fee=app.config["SETTLEMENT_FEE"], merchant_rate=app.config["MERCHANT_RATE"], customer_rate=app.config["CUSTOMER_RATE"], settlement_address=app.config["SETTLEMENT_ADDRESS"])

@app.before_request
def before_request_func():
    if "DEBUG_REQUESTS" in app.config:
        print("URL: %s" % request.url)
        print(request.headers)

    if not current_user.is_anonymous:
        if current_user.has_role("admin") or current_user.has_role("finance"):
            current_user.settlement_wallet_balance = get_update_balance(app.config["SETTLEMENT_ADDRESS"])
        if current_user.wallet_address:
            current_user.wallet_balance = get_update_balance(current_user.wallet_address)

@app.route("/")
def index():
    return render_template("index.html")

#
# Test
#

@app.route("/test/claimcode/<token>")
def test_claimcode(token):
    if not app.config["DEBUG"]:
        return abort(404)
    claim_code = ClaimCode.from_token(db.session, token)
    for api_key in ws_api_keys.keys():
        print("sending claim code to %s" % api_key)
        socketio.emit("info", claim_code.to_json(), json=True, room=api_key)
    if claim_code:
        return jsonify(claim_code.to_json())
    return abort(404)

@app.route("/test/watched")
def test_watched():
    if not app.config["DEBUG"]:
        return abort(404)
    return jsonify(aw.watched())

@app.route("/test/ws")
def test_ws():
    if not app.config["DEBUG"]:
        return abort(404)
    return jsonify(ws_api_keys)

#
# Websocket events
#

def alert_claimed(claim_code):
    for apikey in claim_code.user.apikeys:
        socketio.emit("claimed", claim_code.to_json(), json=True, room=apikey.token)

class SocketIoNamespace(Namespace):
    def trigger_event(self, event, sid, *args):
        if sid not in self.server.environ:
            # we don't have record of this client, ignore this event
            return '', 400
        app = self.server.environ[sid]['flask.app']
        if "DEBUG_REQUESTS" in app.config:
            with app.request_context(self.server.environ[sid]):
                before_request_func()
        return super(SocketIoNamespace, self).trigger_event(event, sid, *args)

    def on_error(self, e):
        print(e)

    def on_connect(self):
        print("connect sid: %s" % request.sid)

    def on_auth(self, auth):
        # check auth
        res, reason, api_key = check_auth(auth["api_key"], auth["nonce"], auth["signature"], str(auth["nonce"]))
        if res:
            emit("info", "authenticated!")
            # join room and store user
            print("join room for api_key: %s" % auth["api_key"])
            join_room(auth["api_key"])
            ws_api_keys[auth["api_key"]] = request.sid
            ws_sids[request.sid] = auth["api_key"]

    def on_disconnect(self):
        print("disconnect sid: %s" % request.sid)
        if request.sid in ws_sids:
            api_key = ws_sids[request.sid]
            if api_key in ws_api_keys:
                print("leave room for api key: %s" % api_key)
                leave_room(api_key)
                del ws_api_keys[api_key]
            del ws_sids[request.sid]

socketio.on_namespace(SocketIoNamespace("/"))

#
# Private (merchant) API
#

@app.route("/watch", methods=["POST"])
def watch():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    addr = content["address"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    aw.watch(addr, api_key.token)
    return "ok"

@app.route("/register", methods=["POST"])
def register():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    token = content["token"]
    amount = content["amount"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    claim_code = ClaimCode(api_key.user, token, amount)
    db.session.add(claim_code)
    db.session.commit()
    return jsonify(claim_code.to_json())

@app.route("/check", methods=["POST"])
def check():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    token = content["token"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    claim_code = ClaimCode.from_token(db.session, token)
    if claim_code and claim_code.user == api_key.user:
        return jsonify(claim_code.to_json())
    return abort(404)

@app.route("/merchanttx", methods=["POST"])
def merchanttx():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    MerchantTx.update_wallet_address(db.session, api_key.user)
    return "ok"

@app.route("/wallet_address", methods=["POST"])
def wallet_address():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    address = content["address"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    if not api_key.account_admin:
        return bad_request("not account admin")
    if api_key.user.wallet_address:
        return bad_request("wallet address already set")
    api_key.user.wallet_address = address
    db.session.add(api_key.user)
    db.session.commit()
    return "ok"

@app.route("/rates", methods=["POST"])
def rates():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    settlement_fee = api_key.user.settlement_fee if api_key.user.settlement_fee else app.config["SETTLEMENT_FEE"]
    merchant_rate = api_key.user.merchant_rate if api_key.user.merchant_rate else app.config["MERCHANT_RATE"]
    customer_rate = api_key.user.customer_rate if api_key.user.customer_rate else app.config["CUSTOMER_RATE"]
    rates = {"settlement_fee": str(settlement_fee), "merchant": str(merchant_rate), "customer": str(customer_rate), "settlement_address": app.config["SETTLEMENT_ADDRESS"], "sales_tax": str(app.config["SALES_TAX"])}
    return jsonify(rates)

@app.route("/banks", methods=["POST"])
def banks():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    banks = Bank.from_user(db.session, api_key.user)
    banks = [bank.to_json() for bank in banks]
    return jsonify(banks)

def _settlement_calc(api_key, amount):
    amount_receive = apply_merchant_rate(amount, api_key.user, app.config)
    return int(amount_receive)

@app.route("/settlement_calc", methods=["POST"])
def settlement_calc():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    amount = content["amount"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    amount_receive = _settlement_calc(api_key, amount)
    return jsonify({"amount": amount, "amount_receive": amount_receive})

@app.route("/settlement", methods=["POST"])
def settlement():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    bank = content["bank"]
    amount = content["amount"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    bank = Bank.from_token(db.session, bank)
    if not bank or bank.user != api_key.user:
        return bad_request("invalid bank account")
    amount_receive = _settlement_calc(api_key, amount)
    if amount_receive <= 0:
        return bad_request("Settlement amount less then or equal to 0");
    count_this_month = Settlement.count_this_month(db.session, api_key.user)
    max_this_month = api_key.user.max_settlements_per_month if api_key.user.max_settlements_per_month else 1
    if count_this_month >= max_this_month:
        return bad_request("Settlement count max reached for this month")
    settlement = Settlement(api_key.user, bank, amount, app.config["SETTLEMENT_ADDRESS"], amount_receive)
    db.session.add(settlement)
    db.session.commit()
    return jsonify(settlement.to_json())

@app.route("/settlement_set_txid", methods=["POST"])
def settlement_set_txid():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    token = content["token"]
    txid = content["txid"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return bad_request(reason)
    settlement = Settlement.from_token(db.session, token)
    if not settlement:
        return bad_request("Settlement not found")
    if settlement.user != api_key.user:
        return bad_request("Settlement not found")
    if settlement.txid:
        return bad_request("Transaction ID already set")
    settlement.txid = txid
    settlement.status = Settlement.STATE_SENT_ZAP
    db.session.add(settlement)
    db.session.commit()
    return jsonify(settlement.to_json())

#
# Public (customer) API
#

@app.route("/claim", methods=["POST"])
def claim():
    content = request.json
    token = content["token"]
    secret = content["secret"]
    address = content["address"]
    claim_code = ClaimCode.from_token(db.session, token)
    if claim_code:
        if claim_code.status == "created":
            claim_code.secret = secret
            claim_code.address = address
            claim_code.status = "claimed"
            alert_claimed(claim_code)
            db.session.add(claim_code)
            db.session.commit()
            return jsonify(claim_code.to_json())
        else:
            return bad_request("already claimed")
    return abort(404)

if __name__ == "__main__":
    setup_logging(logging.DEBUG)
    logger.info("starting server..")

    # create tables
    logger.info("creating tables..")
    db.create_all()
    create_role("admin", "super user")
    create_role("finance", "Can view/action settlements")
    db.session.commit()

    # process commands
    if len(sys.argv) > 1:
        if sys.argv[1] == "add_user":
            add_user(sys.argv[2], sys.argv[3])
        if sys.argv[1] == "add_role":
            add_role(sys.argv[2], sys.argv[3])
        if sys.argv[1] == "add_merchant_codes":
            add_merchant_codes()
    else:
        # check config
        if "SETTLEMENT_ADDRESS" not in app.config:
            logger.error("SETTLEMENT_ADDRESS does not exist")
            sys.exit(1)
        if "SENDER_BANK_ACCOUNT" not in app.config:
            logger.error("SENDER_BANK_ACCOUNT does not exist")
            sys.exit(1)
        if "SENDER_NAME" not in app.config:
            logger.error("SENDER_NAME does not exist")
            sys.exit(1)

        # Bind to PORT if defined, otherwise default to 5000.
        port = int(os.environ.get("PORT", 5000))
        logger.info("binding to port: %d" % port)
        socketio.run(app, host="0.0.0.0", port=port)
        # stop addresswatcher
        if aw:
            aw.kill()
