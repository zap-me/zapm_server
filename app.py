#!/usr/bin/python3
import os
import logging
import time
import sys

from flask import Flask, request, jsonify, abort, redirect, url_for, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
from flask_login import UserMixin, LoginManager, current_user, login_user, logout_user
#from flask_wtf import FlaskForm ### May not be needed
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash

from database import db_session, init_db
from models import ClaimCode
import os
###


init_db()
logger = logging.getLogger(__name__)
app = Flask(__name__)

if os.getenv("DATABASE_URL"):
    db_url = os.getenv("DATABASE_URL")
else:
    dir_path = os.path.dirname(os.path.realpath(__file__))
    #db_url = "sqlite:///%s/zapm-test.db" % dir_path
    db_url = "sqlite:///zapm-test.db" % dir_path



#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zapm-test.db'
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SECRET_KEY'] = 'c#X&bvhr7zPHFNO2V&cuw7QziCOJ%NPNyJOIS02TFq&*S7HXA57q%Smhleh2zPyv'


db = SQLAlchemy(app)
login = LoginManager(app)


def setup_logging(level):
    # setup logging
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter("[%(name)s %(levelname)s] %(message)s"))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()


#### load user function for authentication
@login.user_loader
def load_user(user_id):
    return users.query.get(user_id)

### This BLOCK is to show the the tables as TABS
class users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    username = db.Column(db.String)
    email = db.Column(db.String)
    password = db.Column(db.String)
    wallet_address = db.Column(db.String)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)

class claim_codes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Float, nullable=False)
    token = db.Column(db.String)
    secret = db.Column(db.String)
    address = db.Column(db.String)
    status = db.Column(db.String)

### Protect claim_codes view from viewing normally.
class protected_claim_codes_views(ModelView):
    #form_base_class = flask_wtf.Form  ### NOt Working
    can_delete = False                 ### CAN REMOVE ADMINS ACCESS TO DELETE ROWS
    can_edit = False                   ### REMOVE OVERALL EDIT FUNCTION
    column_exclude_list = ['secret']   ### CAN EXCLUDE COLUMNS FROM BEING DISPLAYED
    #column_editable_list = ['address']   ### ONLY ALLOW CERTAIN COLUMNS TO BE EDITABLE
    page_size = 50 
    def is_accessible(self):
        return current_user.is_authenticated

    ### login when you havent login yet.
    def inaccessible_callback(self, name, **kwargs):
        flash('Login Required!!!')
        return redirect(url_for('login'))

### Change the view for users view
class protected_users_views(ModelView):
    #form_base_class = flask_wtf.Form ### Not Working
    def is_accessible(self):
        return current_user.is_authenticated

    ### login when you havent login yet.
    def inaccessible_callback(self, name, **kwargs):
        #return redirect(url_for('login'))
        flash('Login Required!!!')
        return redirect(url_for('login'))

class protectedAdminIndexView(AdminIndexView):
    #form_base_class = flask_wtf.Form ###Not Working
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        flash('Login Required!!!')
        return redirect(url_for('login'))

#### Menu Links (TOP NAVIGATION BAR)
class AuthenticatedMenuLink(MenuLink):
    def is_accessible(self):
        return current_user.is_authenticated

class NotAuthenticatedMenuLink(MenuLink):
    def is_accessible(self):
        return not current_user.is_authenticated


admin = Admin(app, template_mode='bootstrap3',index_view=protectedAdminIndexView())
admin.add_view(protected_users_views(users, db.session))
admin.add_view(protected_claim_codes_views(claim_codes, db.session))
admin.add_link(AuthenticatedMenuLink(name='Logout', endpoint='logout'))

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

#
# ADMIN API
#

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))
    return render_template('admin/login.html')

@app.route('/login',methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('admin/login.html')

    username = request.form.get('username')
    password = request.form.get('password')

    registered_user = users.query.filter_by(username=username).first()  ###Look for the user in the users table in the db. Return the first user it sees.

    ### POST SECTION OF THE LOGIN PAGE
    if registered_user:
        if registered_user.check_password(password=password):
            login_user(registered_user)
            return redirect(url_for('index'))

    flash('Please check your login details and try again.')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    logout_user()
    flash('User has been logout')
    return redirect(url_for('index'))

if __name__ == "__main__":
    setup_logging(logging.DEBUG)

    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
