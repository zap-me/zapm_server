import datetime

from flask import redirect, url_for, request
from flask_admin.babel import lazy_gettext
from flask_admin.contrib.sqla import tools
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from flask_admin.model import filters
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from flask_admin.contrib import sqla
from marshmallow import Schema, fields

from app_core import app, db

# Define models
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

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

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

    def __str__(self):
        return self.email

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Create customized model view class
class RestrictedModelView(sqla.ModelView):
    can_create = False
    can_delete = False
    can_edit = False
    can_export = True
    column_exclude_list = ['password', 'secret']

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('admin')
        )

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

class ClaimCodeSchema(Schema):
    date = fields.Float()
    token = fields.String()
    secret = fields.String()
    address = fields.String()
    status = fields.String()

class ClaimCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime())
    token = db.Column(db.String(255), unique=True, nullable=False)
    secret = db.Column(db.String(255))
    address = db.Column(db.String(255))
    status = db.Column(db.String(255))

    def __init__(self, token):
        self.date = datetime.datetime.now()
        self.token = token
        self.secret = None
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

#class ClaimsCodeRestrictedModelView(sqla.ModelView):
class ClaimsCodeRestrictedModelView(RestrictedModelView):
    can_create = False
    can_delete = False
    can_edit = False
    can_export = True

    column_exclude_list = ['password', 'secret']
    column_list = ('date', 'token', 'address', 'status')
    column_labels = {
            'date' : 'Date Created',
            'newdate': 'Date Authorised'
    }
    column_filters = [ DateBetweenFilter(ClaimCode.date, 'Search Date'), DateTimeGreaterFilter(ClaimCode.date, 'Search Date'), DateSmallerFilter(ClaimCode.date, 'Search Date'), FilterEqual(ClaimCode.status, 'Search Status'), FilterNotEqual(ClaimCode.status, 'Search Status') ]


    def is_accessible(self):
        #column_exclude_list = ['password', 'secret']

        if not current_user.is_active or not current_user.is_authenticated:
            return False

        if current_user.has_role('admin'):
            self.can_create = True
            self.can_edit = True
            self.can_delete = True
            self.can_export = True
            return True
        if current_user.has_role('authorizer'):
            self.can_create = False
            self.can_delete = False
            self.can_edit = False
            self.can_export = True
            return True
        if current_user.has_role('proposer'):
            self.can_create = False
            self.can_delete = False
            self.can_edit = False
            self.can_export = True
            return True
        if current_user.has_role('viewer'):
            self.can_create = False
            self.can_delete = False
            self.can_edit = False
            self.can_export = False
            return True

        return False

    def handle_view(self, name, **kwargs):
        if current_user.is_authenticated:
            abort(403)
        else:
            # login
            return redirect(url_for('security.login', next=request.url))
        return False

    def _authorized_button():
        _html = '''
            <form action="{checkout_url}" method="POST">
                 <input id="student_id" name="student_id"  type="hidden" value="{student_id}">
                 <button type='submit'>Checkout</button>
            </form
        '''.format(checkout_url=checkout_url, student_id=model.id)

        return Markup(_html)

        column_formatters = {
            'Action': _authorized_button
        }

