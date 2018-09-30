from sqlalchemy import Column, Integer, ForeignKey, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()

class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    @property
    def serialize(self):
        """Return category data in easily serializeable format"""
        return {
        'id' : self.id,
        'name' : self.name
        }

    def __init__(self, id, name):
        self.id = id
        self.name = name

    def __repr__(self):
        return "<Category('%s', '%s')>" % (self.id, self.name)

class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    title = Column(String)
    description = Column(String)
    cat_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        'cat_id' : self.cat_id,
        'description' : self.description,
        'id' : self.id,
        'title' : self.title
        }

    def __init__(self, id, title, description, cat_id):
        self.id = id
        self.title = title
        self.description = description
        self.cat_id = cat_id

    def __repr__(self):
        return "<Item('%s', '%s', '%s', '%s')>" % (self.id, self.title, self.description, self.cat_id)

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
    	s = Serializer(secret_key, expires_in = expiration)
    	return s.dumps({'id': self.id })

    @staticmethod
    def verify_auth_token(token):
    	s = Serializer(secret_key)
    	try:
    		data = s.loads(token)
    	except SignatureExpired:
    		#Valid Token, but expired
    		return None
    	except BadSignature:
    		#Invalid Token
    		return None
    	user_id = data['id']
    	return user_id


engine = create_engine('sqlite:///catalog.db')


Base.metadata.create_all(engine)
