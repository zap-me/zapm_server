#!/usr/bin/python3
import os
import logging
import time
import sys

from flask import Flask, request, jsonify, abort

from database import db_session, init_db
from models import ClaimCode

init_db()
logger = logging.getLogger(__name__)
app = Flask(__name__)

def setup_logging(level):
    # setup logging
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter("[%(name)s %(levelname)s] %(message)s"))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

@app.route("/")
def hello():
    return "boo"

#
# Test
#

@app.route("/test/<token>")
def test(token):
    #TODO: only allow when test environment var is present 
    claim_code = ClaimCode.from_token(db_session, token)
    if claim_code:
        return jsonify(claim_code.to_json())
    return abort(404)

#
# Private (merchant) API
#

@app.route("/register", methods=["POST"])
def register():
    #TODO: add AUTH
    content = request.json
    token = content["token"]
    claim_code = ClaimCode(token)
    db_session.add(claim_code)
    db_session.commit()
    return jsonify(claim_code.to_json())

@app.route("/check", methods=["POST"])
def check():
    #TODO: add AUTH
    content = request.json
    token = content["token"]
    claim_code = ClaimCode.from_token(db_session, token)
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
    claim_code = ClaimCode.from_token(db_session, token)
    if claim_code:
        if claim_code.status == "created":
            claim_code.secret = secret
            claim_code.address = address
            claim_code.status = "claimed"
            db_session.add(claim_code)
            db_session.commit()
            return jsonify(claim_code.to_json())
        else:
            return abort(400, "already claimed")
    return abort(404)

if __name__ == "__main__":
    setup_logging(logging.DEBUG)

    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
