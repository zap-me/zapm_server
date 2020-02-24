#!/usr/bin/python3
import os
import logging
import sys
import json

from flask import url_for, redirect, render_template, request, abort, jsonify
from flask_security.utils import encrypt_password
from flask_socketio import Namespace, emit, join_room, leave_room

from app_core import app, db, socketio
from models import security, user_datastore, Role, User, ClaimCode, TxNotification, ApiKey, MerchantTx, Settlement
import admin
from utils import check_hmac_auth
from addresswatcher import AddressWatcher

logger = logging.getLogger(__name__)
ws_api_keys = {}
ws_sids = {}
aw = None

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

def add_role(email, role_name):
    with app.app_context():
        user = User.from_email(db.session, email)
        if not user:
            logger.error("user does not exist")
            return
        role = Role.from_name(db.session, role_name)
        if not role:
            role = Role(name=role_name)
            db.session.add(role)
            user.roles.append(role)
        elif role not in user.roles:
            user.roles.append(role)
        else:
            logger.info("user already has role")
        db.session.commit()

def check_auth(api_key_token, nonce, sig, body):
    api_key = ApiKey.from_token(db.session, api_key_token)
    if not api_key:
        return False, "not found", None
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
        print("sending 'claimed' event to room %s" % api_key)
        socketio.emit("tx", txt, json=True, room=api_key)
        api_key = ApiKey.from_token(db.session, api_key)
        txnoti = TxNotification(api_key.user, tx["id"])
        db.session.add(txnoti)
        db.session.commit()

@app.before_first_request
def start_address_watcher():
    global aw
    if aw is None:
        aw = AddressWatcher(transfer_tx_callback, True)
        aw.start()

#
# Flask views
#

@app.context_processor
def inject_rates():
    return dict(merchant_rate=app.config["MERCHANT_RATE"], customer_rate=app.config["CUSTOMER_RATE"], settlement_address=app.config["SETTLEMENT_ADDRESS"])

@app.before_request
def before_request_func():
    if "DEBUG_REQUESTS" in app.config:
        print("URL: %s" % request.url)
        print(request.headers)

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
        print("connect %s" % request.sid)

    def on_auth(self, auth):
        # check auth
        res, reason, api_key = check_auth(auth["api_key"], auth["nonce"], auth["signature"], str(auth["nonce"]))
        if res:
            emit("info", "authenticated!")
            # join room and store user
            join_room(auth["api_key"])
            ws_api_keys[auth["api_key"]] = request.sid
            ws_sids[request.sid] = auth["api_key"]

    def on_disconnect(self):
        print("disconnect sid: %s" % request.sid)
        if request.sid in ws_sids:
            api_key = ws_sids[request.sid]
            if api_key in ws_api_keys:
                print("disconnect api key: %s" % api_key)
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
        return abort(400, reason)
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
        return abort(400, reason)
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
        return abort(400, reason)
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
    wallet_address = content["wallet_address"]
    amount = content["amount"]
    txid = content["txid"]
    direction = content["direction"]
    category = content["category"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return abort(400, reason)
    merchant_tx = MerchantTx(api_key.user, wallet_address, amount, txid, direction, category)
    db.session.add(merchant_tx)
    db.session.commit()
    return jsonify(merchant_tx.to_json())

@app.route("/rates", methods=["POST"])
def rates():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return abort(400, reason)
    rates = {"merchant": str(app.config["MERCHANT_RATE"]), "customer": str(app.config["CUSTOMER_RATE"]), "settlement_address": app.config["SETTLEMENT_ADDRESS"]}
    return jsonify(rates)

@app.route("/settlement", methods=["POST"])
def settlement():
    sig = request.headers.get("X-Signature")
    content = request.json
    api_key = content["api_key"]
    nonce = content["nonce"]
    bank_account = content["bank_account"]
    amount = content["amount"]
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return abort(400, reason)
    amount_receive = amount * (1 - app.config["MERCHANT_RATE"])
    amount_receive = int(amount_receive)
    settlement = Settlement(api_key.user, bank_account, amount, amount_receive)
    if settlement.any_this_month(db.session, api_key.user):
        return abort(400, "Settlement already exists for this month")
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
        return abort(400, reason)
    settlement = Settlement.from_token(db.session, token)
    if not settlement:
        return abort(400, "Settlement not found")
    if settlement.user != api_key.user:
        return abort(400, "Settlement not found")
    if settlement.txid:
        return abort(400, "Transaction ID already set")
    settlement.txid = txid
    settlement.status = "awaiting_settlement"
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
            return abort(400, "already claimed")
    return abort(404)

if __name__ == "__main__":
    setup_logging(logging.DEBUG)

    # create tables
    db.create_all()
    db.session.commit()

    # process commands
    if len(sys.argv) > 1:
        if sys.argv[1] == "add_user":
            add_user(sys.argv[2], sys.argv[3])
        if sys.argv[1] == "add_role":
            add_role(sys.argv[2], sys.argv[3])
    else:
        # check config
        if "SETTLEMENT_ADDRESS" not in app.config:
            logger.error("SETTLEMENT_ADDRESS does not exist")
            sys.exit(1)

        # Bind to PORT if defined, otherwise default to 5000.
        port = int(os.environ.get("PORT", 5000))
        print("binding to port: %d" % port)
        socketio.run(app, host="0.0.0.0", port=port)
        # stop addresswatcher
        if aw:
            aw.kill()
