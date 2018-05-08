from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from datetime import datetime

engine = create_engine('sqlite:///categorywithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

user1 = User(name="peizhizhang", email="peizhizhang98@gmail.com")
session.add(user1)
session.commit()


category1 = Category(name="Soccer", user=user1)
session.add(category1)
session.commit()

item1 = Item(name="Jersey", category=category1, user=user1)
session.add(item1)
session.commit()

item2 = Item(name="Royal Madrid", category=category1, user=user1)

session.add(item2)
session.commit()


item3 = Item(name="Shinguards", category=category1, user=user1)

session.add(item3)
session.commit()
