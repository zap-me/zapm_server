from flask import url_for
import flask_admin
from flask_admin import helpers as admin_helpers

from app_core import app, db
from models import security, RestrictedModelView, ApiKeyModelView, ClaimCodeRestrictedModelView, TxNotificationRestrictedModelView, MerchantTxRestrictedModelView, SettlementAdminModelView, SettlementRestrictedModelView, Role, User, ClaimCode, TxNotification, ApiKey, MerchantTx, Settlement

# Create admin
admin = flask_admin.Admin(
    app,
    'Zap Merchant Server',
    base_template='my_master.html',
    template_mode='bootstrap3',
)

# Add model views
admin.add_view(RestrictedModelView(Role, db.session, category='Users'))
admin.add_view(RestrictedModelView(User, db.session, category='Users'))
admin.add_view(ClaimCodeRestrictedModelView(ClaimCode, db.session, category='Reports'))
admin.add_view(TxNotificationRestrictedModelView(TxNotification, db.session, category='Reports'))
admin.add_view(ApiKeyModelView(ApiKey, db.session))
admin.add_view(MerchantTxRestrictedModelView(MerchantTx, db.session, category='Reports'))
admin.add_view(SettlementAdminModelView(Settlement, db.session, category='Reports'))
admin.add_view(SettlementRestrictedModelView(Settlement, db.session, endpoint='SettlementUser', category='Reports'))

# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for
    )

