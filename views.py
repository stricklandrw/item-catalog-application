from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash
from flask import session as login_session
from flask import make_response
from sqlalchemy import create_engine, asc, desc, func
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Item, User
import random
import string
import json
import requests
# Imports for GConnect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json',
                            'r').read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db?check_same_thread=False')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for
                    x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# GConnect client authentication
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token.
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # Obtain authorization code.
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    print 'Access token is' + str(access_token)
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    print 'Result is' + str(result)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID doesn't match app's."), 401)
        print "Token's client ID doesn't match app's."
        reponse.headers['Content-type'] = 'application/json'
        return response

    # Check to see if user is already logged in.
    stored_access_token = login_session.get('access_token')
    print stored_access_token
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already' +
                                            ' connected.'), 200)
        response.headers['Content-type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    print 'Login session is ' + str(login_session)

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    print 'User info is ' + str(data)

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if user exists, if it does not, create a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src='
    output += login_session['picture']
    output += ' style = "width: 300px; height: 300px; border-radius: 150px; '
    output += '-webkit-border-radius: 150px; -mozilla-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session.
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnects a connected user
    credentials = login_session.get('access_token')
    print credentials
    if credentials is None:
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute HTTP GET request to revoke current token.
    print 'In gdisconnect access token is %s' % login_session['access_token']
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token='
    url += str(login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')
    error_message = result[1]
    result = result[0]
    print result
    print error_message

    if result['status'] == '200':
        # Reset the user's session.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['picture']
        del login_session['email']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    elif result['status'] == '400':
        # Reset the user's session.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['picture']
        del login_session['email']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # For whatever reason, the given token was invalid.
        response = make_response(json.dumps('Failed to revoke token for given'
                                            + ' user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# JSON APIs to view catalog information
@app.route('/catalog.json')
def catalogJSON():
    categories = session.query(Category)
    print categories
    return jsonify(Category=[c.serialize for c in categories.all()])

# Show all categories with latest 10 items
@app.route('/')
@app.route('/catalog/')
def showcatalogs():
    # Get all category information
    categories = session.query(Category).all()
    for c in categories:
        print c
    # Retrieve last 10 items added to the database
    items = (session.query(Item, Category)
             .join(Category, Item.cat_id == Category.id)
             .order_by(desc(Item.id))
             .limit(10)
             )
    for i in items:
        print i
    if 'username' in login_session:
        return render_template('catalogs.html', categories=categories,
                               items=items)
    else:
        return render_template('publiccatalogs.html', categories=categories,
                               items=items)

# Show all items in a category
@app.route('/catalog/<category>/items')
def showItems(category):
    # Get all category information
    categories = session.query(Category).all()
    print category
    # Retrieve all items for a given category
    items = (session.query(Item, Category)
             .join(Category, Item.cat_id == Category.id)
             .filter(Category.name == category)
             .all()
             )
    print items
    # Count the number of items retrieved from database
    # TO DO - Replace with database count query
    count = 0
    for item in items:
        count += 1
    print count
    if 'username' in login_session:
        return render_template('items.html', category=category,
                               categories=categories, items=items, count=count)
    else:
        return render_template('publicitems.html', category=category,
                               categories=categories, items=items, count=count)

# Return item information via JSON
@app.route('/catalog/<category>/<item>/JSON')
def itemJSON(category, item):
    item = (session.query(Item, Category)
            .join(Category, Item.cat_id == Category.id)
            .filter(Category.name == category, Item.title == item)
            .one()
            )
    # Pull only the item due to the db join in the query to find the right item.
    item = item[0]
    return jsonify(Item=item.serialize)

# Show specific item information
@app.route('/catalog/<category>/<item>/')
def itemInfo(category, item):
    # Get all category information
    categories = session.query(Category).all()
    print item
    print category
    # Retrieve requested item of the given category
    item = (session.query(Item, Category)
            .join(Category, Item.cat_id == Category.id)
            .filter(Category.name == category, Item.title == item)
            .one()
            )
    print item
    if 'username' in login_session:
        return render_template('item.html', categories=categories, item=item)
    else:
        return render_template('publicitem.html', categories=categories,
                               item=item)

# Create a new menu item
@app.route('/catalog/additem', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        # Provide conversion between categories and category id.
        # Uncomment the following for troubleshooting/debugging
        # title = request.form['name']
        # description = request.form['description']
        # category_id = request.form['category']
        # print title
        # print description
        # print category_id
        # Get user information from form and check against database
        user_id = (session.query(User)
                   .filter(User.username == login_session['username'])
                   .one()
                   )
        print user_id
        # TO DO - use new function to review/format inputs to insert into db
        # Build item for input into database
        newItem = Item(title=request.form['name'],
                       description=request.form['description'],
                       cat_id=request.form['category'],
                       user_id=user_id.id)
        session.add(newItem)
        session.commit()
        flash('New Item %s Successfully Created' % (newItem.title))
        return redirect(url_for('showcatalogs'))
    else:
        # Get all category information
        categories = session.query(Category).all()
        return render_template('newitem.html', categories=categories)

# Edit a menu item
@app.route('/catalog/<category>/<item>/edit', methods=['GET', 'POST'])
def editItem(category, item):
    if 'username' not in login_session:
        return redirect('/login')
    user_id = (session.query(User)
               .filter(User.username == login_session['username'])
               .one()
               )
    # print user_id
    # print user_id.id
    # Get item and category from database to provide information to edit
    editedItem = (session.query(Item, Category)
                  .join(Category, Item.cat_id == Category.id)
                  .filter(Category.name == category, Item.title == item)
                  .one()
                  )
    # print editedItem
    # Get all category information
    categories = session.query(Category).all()
    # print login_session
    # Get item from database to provide information to edit
    changeItem = (session.query(Item)
                  .filter_by(id=editedItem.Item.id)
                  .one()
                  )
    # Reject attempt to edit if not the creator
    if editedItem.Item.user_id != user_id.id:
        return "<script>function myFunction() \
                {alert('You are not authorized to edit this item. Please \
                create your own item in order to edit.');}</script><body \
                onload='myFunction()''>"
    if request.method == 'POST':
        # TO DO - use new function to review/format inputs to insert into db
        if request.form['name']:
            changeItem.title = request.form['name']
        if request.form['description']:
            changeItem.description = request.form['description']
        if request.form['category']:
            changeItem.cat_id = request.form['category']
        session.add(changeItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showcatalogs', categories=categories))
    else:
        return render_template('editItem.html', categories=categories,
                               item=editedItem)

# Delete a menu item
@app.route('/catalog/<category>/<item>/delete', methods=['GET', 'POST'])
def deleteItem(category, item):
    if 'username' not in login_session:
        return redirect('/login')
    # Get item and category from database to provide information to be deleted
    itemToDelete = (session.query(Item, Category)
                    .join(Category, Item.cat_id == Category.id)
                    .filter(Category.name == category, Item.title == item)
                    .one()
                    )
    print itemToDelete
    # Reject attempt to delete if not the creator
    if itemToDelete.Item.user_id != login_session['user_id']:
        return "<script>function myFunction() \
                {alert('You are not authorized to delete this item. Please \
                create your own item in order to delete.');}</script><body \
                onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete.Item)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showItems',
                                category=itemToDelete.Category.name))
    else:
        # Get all category information
        categories = session.query(Category).all()
        return render_template('deleteItem.html', categories=categories,
                               item=itemToDelete)


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def createUser(login_session):
    newUser = User(username=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture']
                   )
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# TO DO
# Add new function to review and format inputs to insert into database


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
