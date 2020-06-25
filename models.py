import datetime
from datetime import timezone
import decimal
import logging
import io
import json
from urllib.parse import urlparse

from flask import redirect, url_for, request, abort, flash, has_app_context, g
from flask_admin import expose
from flask_admin.actions import action
from flask_admin.babel import lazy_gettext
from flask_admin.model import filters
from flask_admin.contrib import sqla
from sqlalchemy import and_
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from wtforms import ValidationError
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from marshmallow import Schema, fields
from markupsafe import Markup
import base58
import qrcode
import qrcode.image.svg

from app_core import app, db, aw
from utils import generate_key, ib4b_response, bankaccount_is_valid, blockchain_transactions, apply_merchant_rate

logger = logging.getLogger(__name__)

#
# Define models
#

roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    @classmethod
    def from_name(cls, session, name):
        return session.query(cls).filter(cls.name == name).first()

    def __str__(self):
        return self.name

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    merchant_name = db.Column(db.String(255))
    merchant_code = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    max_settlements_per_month = db.Column(db.Integer)
    merchant_rate = db.Column(db.Numeric)
    customer_rate = db.Column(db.Numeric)
    wallet_address = db.Column(db.String(255))

    def __init__(self, **kwargs):
        self.merchant_code = generate_key(4)
        super().__init__(**kwargs)

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

    @classmethod
    def all(cls, session):
        return session.query(cls).all()

    def __str__(self):
        return '%s (%s)' % (self.merchant_code, self.merchant_name)

class BankSchema(Schema):
    token = fields.String()
    account_number = fields.String()
    account_name = fields.String()
    account_holder_address = fields.String()
    bank_name = fields.String()
    default_account = fields.Bool()

class Bank(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('banks', lazy='dynamic'))
    token = db.Column(db.String(255), unique=True, nullable=False)
    account_number = db.Column(db.String(255), nullable=False)
    account_name = db.Column(db.String(255), nullable=False)
    account_holder_address = db.Column(db.String(255), nullable=False)
    bank_name = db.Column(db.String(255), nullable=False)
    default_account = db.Column(db.Boolean, nullable=False)

    def __init__(self, token, account_number, account_name, account_holder_address, bank_name, default_account):
        self.account_number = account_number
        self.account_name = account_name
        self.account_holder_address = acount_holder_address
        self.bank_name = bank_name
        self.default_account = default_account
        self.generate_defaults()

    def generate_defaults(self):
        self.user = current_user
        self.token = generate_key(4)

    def ensure_default_account_exclusive(self, session):
        if self.default_account:
            session.query(Bank).filter(Bank.user_id == self.user_id, Bank.id != self.id).update(dict(default_account=False))

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def from_user(cls, session, user):
        return session.query(cls).filter(cls.user_id == user.id).all()

    def __repr__(self):
        return self.account_number

    def to_json(self):
        schema = BankSchema()
        return schema.dump(self).data

class ClaimCodeSchema(Schema):
    date = fields.Float()
    token = fields.String()
    secret = fields.String()
    amount = fields.Integer()
    address = fields.String()
    status = fields.String()

class ClaimCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('claimcodes', lazy='dynamic'))
    date = db.Column(db.DateTime())
    token = db.Column(db.String(255), unique=True, nullable=False)
    secret = db.Column(db.String(255))
    amount = db.Column(db.Integer)
    address = db.Column(db.String(255))
    status = db.Column(db.String(255))

    def __init__(self, user, token, amount):
        self.user = user
        self.date = datetime.datetime.now()
        self.token = token
        self.secret = None
        self.amount = amount
        self.address = None
        self.status = "created"

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __repr__(self):
        return "<ClaimCode %r>" % (self.token)

    def to_json(self):
        schema = ClaimCodeSchema()
        return schema.dump(self).data

class TxNotification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('txnotifications', lazy='dynamic'))
    date = db.Column(db.DateTime())
    txid = db.Column(db.String(255), unique=True)

    def __init__(self, user, txid):
        self.user = user
        self.date = datetime.datetime.now()
        self.txid = txid

    @classmethod
    def exists(cls, session, txid):
        return session.query(cls).filter(cls.txid == txid).first()

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    def __repr__(self):
        return "<TxNotification %r>" % (self.txid)

class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('apikeys', lazy='dynamic'))
    date = db.Column(db.DateTime(), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    nonce = db.Column(db.Integer, nullable=False)
    secret = db.Column(db.String(255), nullable=False)
    account_admin = db.Column(db.Boolean, nullable=False)

    def __init__(self, name):
        self.name = name
        self.generate_defaults()

    def generate_defaults(self):
        self.user = current_user
        self.date = datetime.datetime.now()
        self.token = generate_key(8)
        self.nonce = 0
        self.secret = generate_key(16)

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def admin_exists(cls, session, user):
        return session.query(cls).filter(cls.user == user, cls.account_admin == True).first()

    def __repr__(self):
        return "<ApiKey %r>" % (self.token)

class MerchantTxSchema(Schema):
    date = fields.Float()
    wallet_address = fields.String()
    amount = fields.Integer()
    amount_nzd = fields.Integer()
    txid = fields.String()
    direction = fields.Integer()
    device_name = fields.String()

class MerchantTx(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('merchanttxs', lazy='dynamic'))
    wallet_address = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Integer)
    amount_nzd = db.Column(db.Integer)
    txid = db.Column(db.String(255), nullable=False)
    direction = db.Column(db.Boolean, nullable=False)
    category = db.Column(db.String(255))
    attachment = db.Column(db.String(255))
    device_name = db.Column(db.String(255))
    __table_args__ = (db.UniqueConstraint('user_id', 'txid', name='user_txid_uc'),)

    def __init__(self, user, date, wallet_address, amount, amount_nzd, txid, direction, attachment):
        self.date = date
        self.user = user
        self.wallet_address = wallet_address
        self.amount = amount
        self.amount_nzd = amount_nzd
        self.txid = txid
        self.direction = direction
        self.attachment = attachment
        try:
            self.device_name = json.loads(attachment)['device_name']
        except:
            pass
        try:
            self.category = json.loads(attachment)['category']
        except:
            pass

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_txid(cls, session, txid):
        return session.query(cls).filter(cls.txid == txid).first()

    @classmethod
    def oldest_txid(cls, session, user):
        last =  session.query(cls).filter(cls.user_id == user.id).order_by(cls.id.desc()).first()
        if last:
            return last.txid
        return None

    @classmethod
    def exists(cls, session, user, txid):
        return session.query(cls).filter(and_(cls.user_id == user.id), (cls.txid == txid)).scalar()

    @classmethod
    def update_wallet_address(cls, session, user):
        if user.wallet_address:
            # select the merchant_rate to use
            rate = user.merchant_rate if user.merchant_rate else app.config["MERCHANT_RATE"]
            print(':: Merchant Rate is %s ::' % rate) 
            # update txs
            limit = 100
            oldest_txid = None
            txs = []
            while True:
                have_tx = False
                txs = blockchain_transactions(logger, app.config["NODE_ADDRESS"], user.wallet_address, limit, oldest_txid)
                for tx in txs:
                    oldest_txid = tx["id"]
                    have_tx = MerchantTx.exists(db.session, user, oldest_txid)
                    if have_tx:
                        break
                    if tx["type"] == 4 and tx["assetId"] == app.config["ASSET_ID"]:
                        amount_nzd = apply_merchant_rate(tx['amount'], rate)
                        date = datetime.datetime.fromtimestamp(tx['timestamp'] / 1000)
                        session.add(MerchantTx(user, date, user.wallet_address, tx['amount'], amount_nzd, tx['id'], tx['direction'], tx['attachment']))
                if have_tx or len(txs) < limit:
                    break
            session.commit()

    def __repr__(self):
        return"<MerchantTx %r>" % (self.txid)

    def to_json(self):
        schema = MerchantTxSchema()
        return schema.dump(self).data

class SettlementSchema(Schema):
    date = fields.Float()
    token = fields.String()
    bank_account = fields.String()
    amount = fields.Integer()
    settlement_address = fields.String()
    amount_receive = fields.Integer()
    txid = fields.String()
    status = fields.String()

class Settlement(db.Model):
    CREATED = "created"
    SENT_ZAP = "sent_zap"
    VALIDATED = "validated"
    SENT_NZD = "sent_nzd"
    ERROR = "error"

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('settlements', lazy='dynamic'))
    token = db.Column(db.String(255), nullable=False, unique=True)
    bank_id = db.Column(db.Integer, db.ForeignKey('bank.id'), nullable=False)
    bank = db.relationship('Bank', backref=db.backref('settlements', lazy='dynamic'))
    amount = db.Column(db.Integer, nullable=False)
    settlement_address = db.Column(db.String(255), nullable=False)
    amount_receive = db.Column(db.Integer, nullable=False)
    txid = db.Column(db.String(255))
    status = db.Column(db.String(255), nullable=False)

    def __init__(self, user, bank, amount, settlement_address, amount_receive):
        self.date = datetime.datetime.now()
        self.user = user
        self.token = generate_key(4)
        self.bank = bank
        self.amount = amount
        self.settlement_address = settlement_address
        self.amount_receive = amount_receive
        self.txid = None
        self.status = Settlement.CREATED

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    @classmethod
    def count_this_month(cls, session, user):
        now = datetime.datetime.now()
        # month start
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        # month end
        next_month = now.replace(day=28) + datetime.timedelta(days=4)  # this will never fail
        last_day_of_month = next_month - datetime.timedelta(days=next_month.day)
        month_end = last_day_of_month.replace(hour=23, minute=59, second=59, microsecond=999999)
        return session.query(cls).filter(cls.user_id == user.id, cls.date >= month_start, cls.date <= month_end).count()

    @classmethod
    def all_sent_zap(cls, session):
        return session.query(cls).filter(cls.status == cls.SENT_ZAP).all()

    @classmethod
    def all_validated(cls, session):
        return session.query(cls).filter(cls.status == cls.VALIDATED).all()

    @classmethod
    def from_id_list(cls, session, ids):
        return session.query(cls).filter(cls.id.in_(ids)).all()

    def __repr__(self):
        return"<Settlement %r>" % (self.token)

    def to_json(self):
        schema = SettlementSchema()
        return schema.dump(self).data

#
# Setup Flask-Security
#

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

#
# Define model views
#

class DateBetweenFilter(BaseSQLAFilter, filters.BaseDateBetweenFilter):
    def __init__(self, column, name, options=None, data_type=None):
        super(DateBetweenFilter, self).__init__(column,
                                                name,
                                                options,
                                                data_type='daterangepicker')

    def apply(self, query, value, alias=None):
        start, end = value
        return query.filter(self.get_column(alias).between(start, end))

class FilterEqual(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(self.get_column(alias) == value)

    def operation(self):
        return lazy_gettext('equals')

class FilterNotEqual(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(self.get_column(alias) != value)

    def operation(self):
        return lazy_gettext('not equal')

class FilterGreater(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(self.get_column(alias) > value)

    def operation(self):
        return lazy_gettext('greater than')

class FilterSmaller(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(self.get_column(alias) < value)

    def operation(self):
        return lazy_gettext('smaller than')

class DateTimeGreaterFilter(FilterGreater, filters.BaseDateTimeFilter):
    pass

class DateSmallerFilter(FilterSmaller, filters.BaseDateFilter):
    pass

def _format_amount(view, context, model, name):
    if name == 'amount':
        return Markup(model.amount / 100)
    if name == 'amount_receive':
        return Markup(model.amount_receive / 100)
    if name == 'amount_nzd':
        return round((model.amount_nzd / 100),2)

def get_device_names():
    if has_app_context():
        if not hasattr(g, 'device_names'):
            query = db.session.query(MerchantTx.device_name.distinct().label('device_name')).filter(MerchantTx.user_id == current_user.id)
            g.device_names = [row.device_name for row in query.all()]
        for device_name in g.device_names:
            yield device_name, device_name

def get_categories():
    if has_app_context():
        if not hasattr(g, 'categories'):
            query = db.session.query(MerchantTx.category.distinct().label('category')).filter(MerchantTx.user_id == current_user.id, MerchantTx.category != None)
            g.categories = [row.category for row in query.all()]
        for category in g.categories:
            yield category, category

def _format_direction(view, context, model, name):
    if model.direction == 0:
        return Markup('out')
    elif model.direction == 1:
        return Markup('in')

class ReloadingIterator:
    def __init__(self, iterator_factory):
        self.iterator_factory = iterator_factory

    def __iter__(self):
        return self.iterator_factory()

class FilterByDeviceName(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(MerchantTx.device_name == value)

    def operation(self):
        return u'equals'

    def get_options(self, view):
        # This will return a generator which is reloaded every time it is used.
        # Without this we need to restart the server to update the cache of device names.
        return ReloadingIterator(get_device_names)

class FilterByCategory(BaseSQLAFilter):
    def apply(self, query, value):
        return query.filter(MerchantTx.category == value)

    def operation(self):
        return u'equals'

    def get_options(self, view):
        # This will return a generator which is reloaded every time it is used.
        # Without this we need to restart the server to update the cache of device names.
        return ReloadingIterator(get_categories)

class BaseModelView(sqla.ModelView):
    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))

class BaseOnlyUserOwnedModelView(BaseModelView):
    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated)

    def get_query(self):
        return self.session.query(self.model).filter(self.model.user==current_user)

    def get_count_query(self):
        return self.session.query(db.func.count('*')).filter(self.model.user==current_user)

class RestrictedModelView(BaseModelView):
    can_create = False
    can_delete = False
    can_edit = False
    column_exclude_list = ['password', 'secret']

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('admin'))

class UserModelView(RestrictedModelView):
    can_create = False
    can_delete = False
    can_edit = False
    column_list = ['merchant_name', 'merchant_code', 'email', 'roles', 'max_settlements_per_month', 'merchant_rate', 'customer_rate', 'wallet_address']
    column_editable_list = ['merchant_name', 'roles', 'max_settlements_per_month', 'merchant_rate', 'customer_rate']

class BankAdminModelView(RestrictedModelView):
    can_create = False
    can_delete = False
    can_edit = False
    can_export = True

class ClaimCodeModelView(RestrictedModelView):
    can_create = False
    can_delete = False
    can_edit = False
    can_export = True
    column_exclude_list = ['password', 'secret']
    column_export_exclude_list = ['secret']
    column_filters = [ DateBetweenFilter(ClaimCode.date, 'Search Date'), DateTimeGreaterFilter(ClaimCode.date, 'Search Date'), DateSmallerFilter(ClaimCode.date, 'Search Date'), FilterEqual(ClaimCode.status, 'Search Status'), FilterNotEqual(ClaimCode.status, 'Search Status') ]

class TxNotificationModelView(RestrictedModelView):
    can_create = False
    can_delete = False
    can_edit = False
    can_export = True
    column_filters = [ DateBetweenFilter(TxNotification.date, 'Search Date'), DateTimeGreaterFilter(TxNotification.date, 'Search Date'), DateSmallerFilter(TxNotification.date, 'Search Date') ]

class SettlementAdminModelView(RestrictedModelView):
    can_create = False
    can_delete = False
    can_edit = False
    can_export = True
    column_filters = [DateBetweenFilter(Settlement.date, 'Search Date'), DateTimeGreaterFilter(Settlement.date, 'Search Date'), DateSmallerFilter(Settlement.date, 'Search Date'), FilterGreater(Settlement.amount, 'Search Amount'), FilterSmaller(Settlement.amount, 'Search Amount'), FilterEqual(Settlement.status, 'Search Status'), FilterNotEqual(Settlement.status, 'Search Status')]
    list_template = 'settlement_list.html'

    column_formatters = dict(amount=_format_amount, amount_receive=_format_amount)
    column_labels = dict(amount='ZAP Amount', amount_receive='NZD Amount')

    def settlement_validated(self, settlement):
        if not settlement.txid:
            return None
        tx = aw.transfer_tx(settlement.txid)
        if not tx:
            return None
        if tx["recipient"] != settlement.settlement_address:
            logger.error("settlement (%s) tx recipient is not correct" % (settlement.token, tx["recipient"]))
            return False
        if tx["assetId"] != aw.asset_id:
            return False
            logger.error("settlement (%s) tx asset ID (%s) is not correct" % (settlement.token, tx["assetId"]))
        amount = int(decimal.Decimal(tx["amount"]) * 100)
        if amount != settlement.amount:
            logger.error("settlement (%s) tx amount (%d) is not correct" % (settlement.token, amount))
            return False
        if not tx["attachment"]:
            logger.error("settlement (%s) tx attachment is empty" % settlement.token)
            return False
        attachment = base58.b58decode(tx["attachment"]).decode("utf-8")
        if attachment != settlement.token:
            logger.error("settlement (%s) tx attachment (%s) is not correct" % (settlement.token, attachment))
            return False
        return True

    @expose("/validate")
    def validate(self):
        count = 0
        settlements = Settlement.all_sent_zap(db.session)
        for settlement in settlements:
            res = self.settlement_validated(settlement)
            if res == None:
                continue
            if res:
                settlement.status = Settlement.VALIDATED
            else:
                settlement.status = Settlement.ERROR
            count += 1
            db.session.add(settlement)
        db.session.commit()
        flash('%d Settlements validated' % count)
        return redirect('./')

    @expose('/settle', methods=['GET', 'POST'])
    def execute(self):
        process = request.args.get('process', False, bool)
        ids = request.args.get('ids')
        if ids:
            ids = [int(id_) for id_ in ids.split(',')]
            settlements = Settlement.from_id_list(db.session, ids)
        else:
            settlements = Settlement.all_validated(db.session)
        count = len(settlements)
        if process and ids and request.method == 'POST':
            for settlement in settlements:
                settlement.status = Settlement.SENT_NZD
                db.session.add(settlement)
            db.session.commit()
            flash('Settlements processed')
            return redirect('')
        ids = ','.join([str(settlement.id) for settlement in settlements])
        return self.render('settle.html', count=count, settlements=settlements, ids=ids, process=process)

    @expose('/ib4b')
    def ib4b(self):
        ids = request.args.get('ids')
        if ids:
            ids = [int(id_) for id_ in ids.split(',')]
            settlements = Settlement.from_id_list(db.session, ids)
        else:
            abort(400)
        return ib4b_response("bnz_batch.txt", settlements, app.config["SENDER_NAME"], app.config["SENDER_BANK_ACCOUNT"])

class MerchantTxModelView(BaseOnlyUserOwnedModelView):
    can_create = False
    can_delete = False
    can_edit = False
    can_export = True
    column_default_sort = ('date', True)
    column_exclude_list = ['user', 'wallet_address']
    column_formatters = {'amount':_format_amount, 'direction':_format_direction, 'amount_nzd':_format_amount}
    column_list = ['date', 'amount', 'amount_nzd', 'txid', 'direction', 'category', 'attachment', 'device_name']
    column_labels = dict(amount_nzd='Amount (NZD)')
    column_filters = [ DateBetweenFilter(MerchantTx.date, 'Search Date'), DateTimeGreaterFilter(MerchantTx.date, 'Search Date'), DateSmallerFilter(MerchantTx.date, 'Search Date'), FilterGreater(MerchantTx.amount, 'Search Amount'), FilterSmaller(MerchantTx.amount, 'Search Amount'), FilterByDeviceName(MerchantTx.device_name, 'Search Device Name'), FilterByCategory(MerchantTx.category, 'Search Category') ]
    list_template = 'merchanttx_list.html'

    @expose("/update")
    def update(self):
        if not current_user.wallet_address:
            flash('Account does not have wallet address set')
        else:
            MerchantTx.update_wallet_address(db.session, current_user)
            flash('Updated')
        return redirect('./')

class BankModelView(BaseOnlyUserOwnedModelView):
    can_create = True
    can_delete = False
    can_edit = False
    can_export = True
    column_exclude_list = ['user', 'token', 'settlements']
    form_excluded_columns = ['user', 'token', 'settlements']
    column_editable_list = ['default_account']

    def validate_bank_account(form, field):
        if not bankaccount_is_valid(field.data):
            raise ValidationError('invalid bank account')

    form_args = dict(account_number=dict(validators=[validate_bank_account]))

    def on_model_change(self, form, model, is_created):
        if is_created:
            model.generate_defaults()

    def after_model_change(self, form, model, is_created):
        model.ensure_default_account_exclusive(db.session)
        db.session.commit()

class ApiKeyModelView(BaseOnlyUserOwnedModelView):
    can_create = True
    can_delete = True
    can_edit = False
    column_list = ('date', 'name', 'token', 'secret', 'QRCode', 'account_admin')
    form_excluded_columns = ['user', 'date', 'token', 'nonce', 'secret']

    def _format_qrcode(view, context, model, name):
        admin = model.account_admin if model.account_admin else False
        address = model.user.wallet_address if model.user.wallet_address else ''
        url = urlparse(request.base_url)
        scheme = url.scheme
        if 'X-Forwarded-Proto' in request.headers:
            scheme = request.headers['X-Forwarded-Proto']
        server = '{}://{}/'.format(scheme, url.netloc)
        data = 'zapm_apikey:%s?secret=%s&name=%s&admin=%r&address=%s&server=%s' % (model.token, model.secret, model.name, admin, address, server)
        factory = qrcode.image.svg.SvgPathImage
        img = qrcode.make(data, image_factory=factory)
        output = io.BytesIO()
        img.save(output)
        svg = output.getvalue().decode('utf-8')
        modal = '''
<div id="modal_%s" class="modal fade" role="dialog">
  <div class="modal-dialog">
    <!-- Modal content-->
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">x</button>
        <h4>Api Key QR Code</h4>
      </div>
      <div class="modal-body" style="text-align: center">
        %s
      </div>
    </div>
  </div>
</div>''' % (model.token, svg)
        
        link = '<a href="#" data-keyboard="true" data-toggle="modal" data-target="#modal_%s"><img src="/static/qrcode.svg"/></a>' % model.token
        html = '%s %s' % (modal, link)
        return Markup(html)

    column_formatters = dict(QRCode=_format_qrcode)

    def on_model_change(self, form, model, is_created):
        if is_created:
            with db.session.no_autoflush:
                if form.account_admin.data and ApiKey.admin_exists(db.session, current_user):
                    raise ValidationError('Account admin already exists')
            model.generate_defaults()

class SettlementModelView(BaseOnlyUserOwnedModelView):
    can_create = False
    can_delete = False
    can_edit = False
    column_exclude_list = ['user']
    column_export_exclude_list = ['user']

    column_formatters = dict(amount=_format_amount, amount_receive=_format_amount)
    column_labels = dict(amount='ZAP Amount', amount_receive='NZD Amount')
