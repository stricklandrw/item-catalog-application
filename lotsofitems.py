from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, Category, Item

engine = create_engine('sqlite:///catalog.db?check_same_thread=False')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


category1 = Category(name = "Soccer")

session.add(category1)
session.commit()

item1 = Item(name = "Soccer Cleats", cat_id = "1", description = "The shoes")

session.add(item1)
session.commit()

item2 = Item(name = "Jersey", cat_id = "1", description = "The shirt")

session.add(item2)
session.commit()


category2 = Category(name = "Basketball")

session.add(category1)
session.commit()

category3 = Category(name = "Baseball")

session.add(category1)
session.commit()

category4 = Category(name = "Frisbee")

session.add(category1)
session.commit()

category5 = Category(name = "Snowboarding")

session.add(category1)
session.commit()

category6 = Category(name = "Rock Climbing")

session.add(category1)
session.commit()

category7 = Category(name = "Foosball")

session.add(category1)
session.commit()

category8 = Category(name = "Skating")

session.add(category1)
session.commit()

category9 = Category(name = "Hockey")

session.add(category1)
session.commit()
