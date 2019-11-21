#!/usr/bin/python3
import os
import logging
import sys

from flask import url_for, redirect, render_template, request, abort, jsonify
from flask_security.utils import encrypt_password

from app_core import app, db
from models import security, user_datastore, Role, User, ClaimCode, ApiKey
import admin
from utils import check_hmac_auth

logger = logging.getLogger(__name__)

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
            #logger.error('user already exists')
            #return
            user.password = encrypt_password(password)
        else:
            user = user_datastore.create_user(email=email, password=encrypt_password(password))
        db.session.commit()

def add_role(email, role_name):
    with app.app_context():
        user = User.from_email(db.session, email)
        if not user:
            logger.error('user does not exist')
            return
        role = Role.from_name(db.session, role_name)
        if not role:
            role = Role(name=role_name)
            db.session.add(role)
            user.roles.append(role)
        elif role not in user.roles:
            user.roles.append(role)
        else:
            logger.info('user already has role')
        db.session.commit()

#
# Flask views
#

@app.route('/')
def index():
    return render_template('index.html')

#
# Test
#

@app.route("/test/<token>")
def test(token):
    #TODO: only allow when test environment var is present 
    claim_code = ClaimCode.from_token(db.session, token)
    if claim_code:
        return jsonify(claim_code.to_json())
    return abort(404)

#
# Private (merchant) API
#

def check_auth(api_key_token, nonce, sig, body):
    api_key = ApiKey.from_token(db.session, api_key_token)
    if not api_key:
        return False, "not found", None
    res, reason = check_hmac_auth(api_key, nonce, sig, request.data)
    if not res:
        return False, reason, None
    # update api key nonce
    db.session.commit()
    return True, "", api_key

@app.route("/register", methods=["POST"])
def register():
    sig = request.headers.get('X-Signature')
    content = request.json
    api_key = content['api_key']
    nonce = content['nonce']
    token = content['token']
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return abort(400, reason)
    claim_code = ClaimCode(api_key.user, token)
    db.session.add(claim_code)
    db.session.commit()
    return jsonify(claim_code.to_json())

@app.route("/check", methods=["POST"])
def check():
    sig = request.headers.get('X-Signature')
    content = request.json
    api_key = content['api_key']
    nonce = content['nonce']
    token = content['token']
    res, reason, api_key = check_auth(api_key, nonce, sig, request.data)
    if not res:
        return abort(400, reason)
    claim_code = ClaimCode.from_token(db.session, token)
    if claim_code:
        return jsonify(claim_code.to_json())
    return abort(404)

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
    print(sys.argv)
    if len(sys.argv) > 1:
        if sys.argv[1] == 'add_user':
            add_user(sys.argv[2], sys.argv[3])
        if sys.argv[1] == 'add_role':
            add_role(sys.argv[2], sys.argv[3])
    else:
        # Bind to PORT if defined, otherwise default to 5000.
        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port)
