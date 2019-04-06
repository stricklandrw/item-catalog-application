from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, Category, Item, User

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

user1 = User(username="test", picture="", email="test@test.org")

session.add(user1)
session.commit()

category1 = Category(name="Soccer")

session.add(category1)
session.commit()

item1 = Item(title="Soccer Cleats", cat_id="1", description="The shoes",
             user_id="1")

session.add(item1)
session.commit()

item2 = Item(title="Jersey", cat_id="1", description="The shirt", user_id="1")

session.add(item2)
session.commit()


category2 = Category(name="Basketball")

session.add(category2)
session.commit()


category3 = Category(name="Baseball")

session.add(category3)
session.commit()

item3 = Item(title="Bat", cat_id="3", description="The bat", user_id="1")

session.add(item3)
session.commit()


category4 = Category(name="Frisbee")

session.add(category4)
session.commit()

category5 = Category(name="Snowboarding")

session.add(category5)
session.commit()

item7 = Item(title="Snowboard", cat_id="5",
             description="Best for any terrain and conditions. All-mountain" +
             "snowboards perform anywhere on a mountain - groomed ruins, " +
             "backcountry, even park and pipe. They may be directional " +
             "(meaning downhill only) or twin-tip (for riding switch, " +
             "meaning either direction). Most boarders ride all-mountain" +
             " boards. Because of their versatility, all-mountain boards are" +
             " good for beginners who are still learning what terrain they " +
             "like.", user_id="1")

session.add(item7)
session.commit()


category6 = Category(name="Rock Climbing")

session.add(category6)
session.commit()

category7 = Category(name="Foosball")

session.add(category7)
session.commit()

category8 = Category(name="Skating")

session.add(category8)
session.commit()

category9 = Category(name="Hockey")

session.add(category9)
session.commit()

item4 = Item(title="Jersey", cat_id="9", description="The shirt", user_id="1")

session.add(item4)
session.commit()
