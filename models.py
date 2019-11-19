import time

from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey
import sqlalchemy.types as types
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import func
from sqlalchemy import or_, and_, desc
from marshmallow import Schema, fields
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from database import Base

class ClaimCodeSchema(Schema):
    date = fields.Float()
    token = fields.String()
    secret = fields.String()
    address = fields.String()
    status = fields.String()

class ClaimCode(Base):
    __tablename__ = "claim_codes"
    id = Column(Integer, primary_key=True)
    date = Column(Float, nullable=False)
    token = Column(String, nullable=False, unique=True)
    secret = Column(String)
    address = Column(String)
    status = Column(String)

    def __init__(self, token):
        self.date = time.time()
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
    
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    username = Column(String(100), nullable=False, unique=True)
    email = Column(String(100), nullable=False, unique=True)
    password = Column(String(100), nullable=False)
    wallet_address = Column(String(32), nullable=False, unique=True)

    def __init__(self, name, email, mobile, wallet_address):
        self.name = name
        self.username = username
        self.email = email
        self.mobile_number = mobile_number
        self.wallet_address = wallet_address

    def set_password(self, password):
        """create hashed password."""
        self.password = generate_password_hash(password, method='sha256')

    def check_password(self, password):
        """check the hashed password"""
        return check_password_hash(self.password, password)
    



