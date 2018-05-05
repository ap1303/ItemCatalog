import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class Category(Base):
    __tablename__ = 'Category'

    id = Column(Integer, primary_key = True)
    category = Column(String(80), nullable = False)


class Item(Base):
    __tablename__ = 'Item'

    id = Column(Integer, primary_key = True)
    name = Column(String(80), nullable = False)
    category_id = Column(Integer, ForeignKey('Category.id'))
    category = relationship(Category)


engine = create_engine('sqlite:///category.db')
Base.metadata.create_all(engine)
