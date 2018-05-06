from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from datetime import datetime

Base = declarative_base()


class User(Base):
    __tablename__ = 'User'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    __tablename__ = 'Category'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    user_id = Column(Integer, ForeignKey("User.id"))
    user = relationship(User)

    @property
    def serialize(self, category_items):
        items = []
        for item in category_items:
            if item.user_id == id:
                items.append(item.serialize)
        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id,
            'user': self.user,
            'items': items,
        }

class Item(Base):
    __tablename__ = 'Item'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    last_modified = Column(DateTime(), default=datetime.now())
    category_id = Column(Integer, ForeignKey('Category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey("User.id"))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'last_modified': self.last_modified,
            'category_id': self.category_id,
            'category': self.category,
            'user_id': self.user_id,
            'user': self.user,
        }



engine = create_engine('sqlite:///categorywithusers.db')
Base.metadata.create_all(engine)
