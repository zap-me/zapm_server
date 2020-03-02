import datetime
from datetime import timezone
import decimal
import logging

from flask import redirect, url_for, request, abort, flash
from flask_admin import expose
from flask_admin.actions import action
from flask_admin.babel import lazy_gettext
from flask_admin.model import filters
from flask_admin.contrib import sqla
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from marshmallow import Schema, fields
import base58

from app_core import app, db, aw
from utils import generate_key, ib4b_response

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
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    max_settlements_per_month = db.Column(db.Integer)

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

    def __str__(self):
        return self.email

class BankSchema(Schema):
    account_number = fields.String()
    account_name = fields.String()
    account_holder_address = fields.String()
    default_account = db.Column(db.Boolean())
    bank_name = fields.String()

class Bank(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('banks', lazy='dynamic'))
    account_number = db.Column(db.String(255), nullable=False)
    account_name = db.Column(db.String(255), nullable=False)
    account_holder_address = db.Column(db.String(255), nullable=False)
    default_account = db.Column(db.Boolean, nullable=False)
    bank_name = db.Column(db.String(255), nullable=False)

    def __init__(self, account_number, account_name, account_holder_address, default_account, bank_name):
        self.account_name = account_name
        self.account_holder_address = acount_holder_address
        self.account_number = account_number
        self.default_account = default_account
        self.bank_name = bank_name

    def ensure_default_account_exclusive(self, session):
        if self.default_account:
            session.query(Bank).filter(Bank.user_id == self.user_id, Bank.id != self.id).update(dict(default_account=False))

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_account_number(cls, session, account_number):
        return session.query(cls).filter(cls.account_number == account_number).first()

    def __repr__(self):
        return "<Bank %r>" % (self.account_number)

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

    def __repr__(self):
        return "<ApiKey %r>" % (self.token)

class MerchantTxSchema(Schema):
    date = fields.Float()
    wallet_address = fields.String()
    amount = fields.Integer()
    txid = fields.String()
    direction = fields.Integer()
    category = fields.String()

class MerchantTx(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('merchanttxs', lazy='dynamic'))
    wallet_address = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Integer)
    txid = db.Column(db.String(255), nullable=False)
    direction = db.Column(db.Boolean, nullable=False)
    category = db.Column(db.String(255), nullable=False)

    def __init__(self, user, wallet_address, amount, txid, direction, category):
        self.date = datetime.datetime.now()
        self.user = user
        self.wallet_address = wallet_address
        self.amount = amount
        self.txid = txid
        self.direction = direction
        self.category = category

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_txid(cls, session, txid):
        return session.query(cls).filter(cls.txid == txid).first()

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
    bank_account = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    settlement_address = db.Column(db.String(255), nullable=False)
    amount_receive = db.Column(db.Integer, nullable=False)
    txid = db.Column(db.String(255))
    status = db.Column(db.String(255), nullable=False)

    def __init__(self, user, bank_account, amount, settlement_address, amount_receive):
        self.date = datetime.datetime.now()
        self.user = user
        self.token = generate_key(4)
        self.bank_account = bank_account
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
    column_list = ['email', 'roles', 'max_settlements_per_month']
    column_editable_list = ['roles', 'max_settlements_per_month']

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
    column_filters = [ DateBetweenFilter(Settlement.date, 'Search Date'), DateTimeGreaterFilter(Settlement.date, 'Search Date'), DateSmallerFilter(Settlement.date, 'Search Date'), FilterGreater(Settlement.amount, 'Search Amount'), FilterSmaller(Settlement.amount, 'Search Amount'), FilterEqual(Settlement.status, 'Search Status'), FilterNotEqual(Settlement.status, 'Search Status') ]
    list_template = 'settlement_list.html'

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
    column_filters = [ DateBetweenFilter(MerchantTx.date, 'Search Date'), DateTimeGreaterFilter(MerchantTx.date, 'Search Date'), DateSmallerFilter(MerchantTx.date, 'Search Date'), FilterGreater(MerchantTx.amount, 'Search Amount'), FilterSmaller(MerchantTx.amount, 'Search Amount'), FilterEqual(MerchantTx.category, 'Search Category'), FilterNotEqual(MerchantTx.category, 'Search Category') ]

class BankModelView(BaseOnlyUserOwnedModelView):
    can_create = True
    can_delete = False
    can_edit = False
    can_export = True
    column_exclude_list = ['user']
    form_excluded_columns = ['user']
    column_editable_list = ['default_account']

    def on_model_change(self, form, model, is_created):
        if is_created:
            model.user = current_user

    def after_model_change(self, form, model, is_created):
        model.ensure_default_account_exclusive(db.session)
        db.session.commit()

class ApiKeyModelView(BaseOnlyUserOwnedModelView):
    can_create = True
    can_delete = True
    can_edit = False
    column_list = ('date', 'name', 'token', 'secret')
    form_excluded_columns = ['user', 'date', 'token', 'nonce', 'secret']

    def on_model_change(self, form, model, is_created):
        if is_created:
            model.generate_defaults()

class SettlementModelView(BaseOnlyUserOwnedModelView):
    column_exclude_list = ['user']
    column_export_exclude_list = ['user']
