import random
import httplib2
import json
import string
import requests
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
from flask import session as login_session
from flask import make_response


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


# Connect Database and create time_session for database
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
time_bound = DBSession()


def getUserInfo(user_id):
    user = time_bound.query(User).filter_by(id=user_id).one()
    return user


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    time_bound.add(newUser)
    time_bound.commit()
    user = time_bound.query(User).filter_by(email=login_session['email']).one()
    return user.id


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template("Login.html", STATE=state)


def getUserID(email):
    try:
        user = time_bound.query(User).filter_by(email=email).one()
        return user.id
    except BaseException:
        return None


# gconnect


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        get_response = make_response(
            json.dumps('Invalid state parameter.'), 401)
        get_response.headers['Content-Type'] = 'application/json'
        return get_response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        get_response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        get_response.headers['Content-Type'] = 'application/json'
        return get_response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        get_response = make_response(json.dumps(result.get('error')), 500)
        get_response.headers['Content-Type'] = 'application/json'
        return get_response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        get_response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        get_response.headers['Content-Type'] = 'application/json'
        return get_response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        get_response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        get_response.headers['Content-Type'] = 'application/json'
        return get_response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        get_response = make_response(
            json.dumps('Current user is already connected.'), 200)
        get_response.headers['Content-Type'] = 'application/json'
        return get_response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id = getUserID(login_session['email'])

    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    print login_session['username']
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += """ " style = "width: 300px; height: 300px;border-radius: 150px;
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> """
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

    # DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # disconnect a connected user from gmail.
    credentials = login_session.get('credentials')
    if credentials is None:
        get_response = make_response(
            json.dumps('Current user not connected.'), 401)
        get_response.headers['Content-Type'] = 'application/json'
        return get_response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':

        get_response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        get_response.headers['Content-Type'] = 'application/json'
        return get_response


# function to disconnect user from google ID
@app.route('/disconnect')
def disconnect():
    if 'username' in login_session:
        gdisconnect()
        del login_session['gplus_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have successfully been logged out.")
        return redirect(url_for('showRestaurants'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showRestaurants'))


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = time_bound.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)

# JSON APIs to view Restaurant Information


@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = time_bound.query(Restaurant).filter_by(id=restaurant_id).one()
    items = time_bound.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])

# function to show all restaurants


@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    restaurants = time_bound.query(Restaurant).order_by(asc(Restaurant.name))
    if 'username' not in login_session:
        return render_template(
            'PublicRestaurants.html',
            restaurants=restaurants)
    else:
        return render_template('Restaurants.html', restaurants=restaurants)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = time_bound.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


# function to edit name restaurant


@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect("/login")
    editedRestaurant = time_bound.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if login_session['user_id'] != editedRestaurant.user_id:
        flash('edit your restaurant')
        return redirect(url_for('showRestaurants'))
    else:
        if request.method == 'POST':
            if request.form['name']:
                editedRestaurant.name = request.form['name']
                flash(
                    'Restaurant Successfully Edited %s' %
                    editedRestaurant.name)
                return redirect(url_for('showRestaurants'))
        else:
            return render_template(
                'EditRestaurant.html',
                restaurant=editedRestaurant)
# function to create new restaurant


@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    if 'username' not in login_session:
        return redirect("/login")
    if request.method == 'POST':
        newRestaurant = Restaurant(
            name=request.form['name'],
            user_id=login_session['user_id'])
        time_bound.add(newRestaurant)
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        time_bound.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('NewRestaurant.html')


# function to Show  restaurant menu


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = time_bound.query(Restaurant).filter_by(id=restaurant_id).one()
    items = time_bound.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    creator = getUserInfo(restaurant.user_id)
    if "username" not in \
            login_session or login_session['user_id'] != creator.id:
        return render_template(
            'PublicMenu.html',
            items=items,
            restaurant=restaurant,
            creator=creator)
    else:
        return render_template(
            'Menu.html',
            items=items,
            restaurant=restaurant,
            creator=creator)


# function to create  new menu item
@app.route(
    '/restaurant/<int:restaurant_id>/menu/new/',
    methods=[
        'GET',
        'POST'])
def newMenuItem(restaurant_id):
    if 'username' not in login_session:
        return redirect("/login")
    restaurant = time_bound.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        newItem = MenuItem(
            name=request.form['name'],
            description=request.form['description'],
            price=request.form['price'],
            course=request.form['course'],
            restaurant_id=restaurant_id,
            user_id=restaurant.user_id)
        time_bound.add(newItem)
        time_bound.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('NewMenuItem.html', restaurant_id=restaurant_id)

# funciton to delete  restaurant


@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect("/login")
    else:
        restaurantToDelete = time_bound.query(
            Restaurant).filter_by(id=restaurant_id).one()
        if login_session['user_id'] != restaurantToDelete.user_id:
            flash('You can Delete only your restaurant')
            return redirect(url_for('showRestaurants'))
        if request.method == 'POST':
            time_bound.delete(restaurantToDelete)
            flash('%s Successfully Deleted' % restaurantToDelete.name)
            time_bound.commit()
            return redirect(
                url_for(
                    'showRestaurants',
                    restaurant_id=restaurant_id))
        else:
            return render_template(
                'DeleteRestaurant.html',
                restaurant=restaurantToDelete)


# function to delete  menu item
@app.route(
    '/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete',
    methods=[
        'GET',
        'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect("/login")
    else:
        restaurant = time_bound.query(
            Restaurant).filter_by(id=restaurant_id).one()
        itemToDelete = time_bound.query(MenuItem).filter_by(id=menu_id).one()
        if login_session['user_id'] != restaurant.user_id:
            flash('edit your restaurant')
            return redirect(url_for('showRestaurants'))
        if request.method == 'POST':
            time_bound.delete(itemToDelete)
            time_bound.commit()
            flash('Menu Item Successfully Deleted')
            return redirect(url_for('showMenu', restaurant_id=restaurant_id))
        else:
            return render_template('DeleteMenuItem.html', item=itemToDelete)


# function to edit  menu item


@app.route(
    '/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit',
    methods=[
        'GET',
        'POST'])
def editMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect("/login")
    edit_Item = time_bound.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = time_bound.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        flash('edit your restaurant Menu')
        return redirect(url_for('showRestaurants'))
    if request.method == 'POST':
        if request.form['name']:
            edit_Item.name = request.form['name']
        if request.form['description']:
            edit_Item.description = request.form['description']
        if request.form['price']:
            edit_Item.price = request.form['price']
        if request.form['course']:
            edit_Item.course = request.form['course']
        time_bound.add(edit_Item)
        time_bound.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template(
            'EditMenuItem.html',
            restaurant_id=restaurant_id,
            menu_id=menu_id,
            item=edit_Item)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
