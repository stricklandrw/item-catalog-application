from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, catalog, MenuItem, Users

from flask import session as login_session
import random, string

# Imports for GConnect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

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
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
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
        response = make_response(json.dumps('Current user is already connected.'), 200)
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

    # see if user exists, if it does not, create a new one
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
    output += ' style = "width: 300px; height: 300px; border-radius: 150px; -webkit-border-radius: 150px; -mozilla-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session.
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnects a connected user
    credentials = login_session.get('access_token')
    print credentials
    if credentials is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute HTTP GET request to revoke current token.
    print 'In gdisconnect access token is %s' % login_session['access_token']
    print 'User name is: '
    print login_session['username']
    #    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=' + str(login_session['access_token'])
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
#        if error_message[0] == 'invalid_token':
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
        response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

#JSON APIs to view catalog Information
@app.route('/catalog/<int:catalog_id>/menu/JSON')
def catalogMenuJSON(catalog_id):
    catalog = session.query(catalog).filter_by(id = catalog_id).one()
    items = session.query(MenuItem).filter_by(catalog_id = catalog_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/catalog/<int:catalog_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(catalog_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/catalog/JSON')
def catalogsJSON():
    catalogs = session.query(catalog).all()
    return jsonify(catalogs= [r.serialize for r in catalogs])


#Show all categories with latest 10 items
@app.route('/')
@app.route('/catalog/')
def showcatalogs():
    catalogs = session.query(catalog).order_by(asc(catalog.name))
    if 'username' not in login_session:
        return render_template('publiccatalogs.html', catalogs=catalogs)
    else:
        return render_template('catalogs.html', catalogs = catalogs)

#Create a new catalog
@app.route('/catalog/new/', methods=['GET','POST'])
def newcatalog():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newcatalog = catalog(name = request.form['name'], user_id=login_session['user_id'])
        session.add(newcatalog)
        flash('New catalog %s Successfully Created' % newcatalog.name)
        session.commit()
        return redirect(url_for('showcatalogs'))
    else:
        return render_template('newcatalog.html')

#Edit a catalog
@app.route('/catalog/<int:catalog_id>/edit/', methods = ['GET', 'POST'])
def editcatalog(catalog_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedcatalog = session.query(catalog).filter_by(id = catalog_id).one()
    if editedcatalog.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this catalog. Please create your own catalog in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedcatalog.name = request.form['name']
            flash('catalog Successfully Edited %s' % editedcatalog.name)
            return redirect(url_for('showcatalogs'))
    else:
        return render_template('editcatalog.html', catalog = editedcatalog)



#Delete a catalog
@app.route('/catalog/<int:catalog_id>/delete/', methods = ['GET','POST'])
def deletecatalog(catalog_id):
    if 'username' not in login_session:
        return redirect('/login')
    catalogToDelete = session.query(catalog).filter_by(id = catalog_id).one()
    if catalogToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this catalog. Please create your own catalog in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(catalogToDelete)
        flash('%s Successfully Deleted' % catalogToDelete.name)
        session.commit()
        return redirect(url_for('showcatalogs', catalog_id = catalog_id))
    else:
        return render_template('deletecatalog.html',catalog = catalogToDelete)

#Show a catalog menu
@app.route('/catalog/<int:catalog_id>/')
@app.route('/catalog/<int:catalog_id>/menu/')
def showMenu(catalog_id):
    catalog = session.query(catalog).filter_by(id = catalog_id).one()
    items = session.query(MenuItem).filter_by(catalog_id = catalog_id).all()
    creator = getUserInfo(catalog.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicmenu.html', catalog = catalog, creator = creator)
    else:
        return render_template('menu.html', items = items, catalog = catalog, creator = creator)

#Create a new menu item
@app.route('/catalog/<int:catalog_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(catalog_id):
    if 'username' not in login_session:
        return redirect('/login')
    catalog = session.query(catalog).filter_by(id = catalog_id).one()
    if request.method == 'POST':
        newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], course = request.form['course'], catalog_id = catalog_id, user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', catalog_id = catalog_id))
    else:
        return render_template('newmenuitem.html', catalog_id = catalog_id)

#Edit a menu item
@app.route('/catalog/<int:catalog_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(catalog_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
    catalog = session.query(catalog).filter_by(id = catalog_id).one()
    if editedItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this item. Please create your own item in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', catalog_id = catalog_id))
    else:
        return render_template('editmenuitem.html', catalog_id = catalog_id, menu_id = menu_id, item = editedItem)

#Delete a menu item
@app.route('/catalog/<int:catalog_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(catalog_id,menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    catalog = session.query(catalog).filter_by(id = catalog_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one()
    if itemToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this item. Please create your own item in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', catalog_id = catalog_id))
    else:
        return render_template('deleteMenuItem.html', item = itemToDelete)

def getUserID(email):
    try:
        user = session.query(Users).filter_by(email = email).one()
        return user.id
    except:
        return None

def getUserInfo(user_id):
    user = session.query(Users).filter_by(id = user_id).one()
    return user

def createUser(login_session):
    newUser = Users(name = login_session['username'], email = login_session['email'],
                    picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(Users).filter_by(email = login_session['email']).one()
    return user.id

if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 8000)
