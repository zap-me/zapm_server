from flask import url_for
import flask_admin
from flask_admin import helpers as admin_helpers

from app_core import app, db
from models import security, RestrictedModelView, UserModelView, ApiKeyModelView, ClaimCodeModelView, TxNotificationModelView, MerchantTxModelView, SettlementAdminModelView, SettlementModelView, Role, User, ClaimCode, TxNotification, ApiKey, MerchantTx, Settlement

# Create admin
admin = flask_admin.Admin(
    app,
    'Zap Merchant Server',
    base_template='my_master.html',
    template_mode='bootstrap3',
)

# Add model views
admin.add_view(RestrictedModelView(Role, db.session, category='Users'))
admin.add_view(UserModelView(User, db.session, category='Users'))
admin.add_view(ClaimCodeModelView(ClaimCode, db.session, category='Reports'))
admin.add_view(TxNotificationModelView(TxNotification, db.session, category='Reports'))
admin.add_view(ApiKeyModelView(ApiKey, db.session))
admin.add_view(MerchantTxModelView(MerchantTx, db.session, category='Reports'))
admin.add_view(SettlementAdminModelView(Settlement, db.session, category='Reports'))
admin.add_view(SettlementModelView(Settlement, db.session, endpoint='SettlementUser', category='Reports'))

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

