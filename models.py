import time

from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey
import sqlalchemy.types as types
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import func
from sqlalchemy import or_, and_, desc
from marshmallow import Schema, fields

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
    secret = Column(String, nullable=False)
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
