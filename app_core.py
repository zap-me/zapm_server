import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Create Flask application
app = Flask(__name__)
app.config.from_pyfile('config.py')
if os.getenv("DATABASE_URL"):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
if os.getenv("SESSION_KEY"):
    app.config['SECRET_KEY'] = os.getenv("SESSION_KEY")
if os.getenv("PASSWORD_SALT"):
    app.config['SECURITY_PASSWORD_SALT'] = os.getenv("PASSWORD_SALT")
db = SQLAlchemy(app)
