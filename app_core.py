import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail_sendgrid import MailSendGrid
from flask_socketio import SocketIO

# Create Flask application
app = Flask(__name__)
app.config.from_pyfile("config.py")
if os.getenv("DEBUG"):
    app.config["DEBUG"] = True
if os.getenv("DEBUG_REQUESTS"):
    app.config["DEBUG_REQUESTS"] = True
if os.getenv("DATABASE_URL"):
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
if os.getenv("SESSION_KEY"):
    app.config["SECRET_KEY"] = os.getenv("SESSION_KEY")
if os.getenv("PASSWORD_SALT"):
    app.config["SECURITY_PASSWORD_SALT"] = os.getenv("PASSWORD_SALT")
if os.getenv("SENDGRID_API_KEY"):
    app.config["MAIL_SENDGRID_API_KEY"] = os.getenv("SENDGRID_API_KEY")
db = SQLAlchemy(app)
mail = MailSendGrid(app)
socketio = SocketIO(app)
