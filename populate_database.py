from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item
from datetime import datetime

engine = create_engine('sqlite:///categorywithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


category1 = Category(category="Soccer")
session.add(category1)
session.commit()

item1 = Item(name="Jersey", category=category1)
session.add(item1)
session.commit()

item2 = Item(name="Royal Madrid", category=category1)

session.add(item2)
session.commit()


item3 = Item(name="Shinguards", category=category1)

session.add(item3)
session.commit()