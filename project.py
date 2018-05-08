from flask import Flask, render_template, request, flash, jsonify, url_for, redirect, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import random, string
import httplib2
import json
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
engine = create_engine('sqlite:///categorywithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
def home_page():
    output = ''

    output += 'categories'
    output += '</br>'
    categories = session.query(Category).all()
    for cat in categories:
        output += '<a href="/catalog/{0}/items">{1}</a>'.format(cat.category, cat.category)
        output += '</br>'

    if 'username' in login_session:
        output += '<a href="catalog/new">Add Item</a>'
        output += '</br>'
        output += '<a href="/gdisconnect">Disconnect</a>'
        output += '</br>'
    else:
        output += '<a href="/login">Connect</a>'
        output += '</br>'

    return output


@app.route('/catalog/<str:category>/items')
def show_items(category):
    items = session.query(Item).filter_by(category=category).all()
    output = ''
    for item in items:
        output += '<a href="/catalog/{0}/{1}">{2}</a>'.format(category, item, item)

    if 'username' in login_session:
        output += '<a href="catalog/new">Add Item</a>'
        output += '</br>'
        output += '<a href="/gdisconnect">Disconnect</a>'
        output += '</br>'
    else:
        output += '<a href="/login">Connect</a>'
        output += '</br>'
    return output


@app.route('/catalog/<str:category>/<str:item>')
def show_item(category, item):
    output = '<div>{0}'.format(item)
    output += session.query(Item).filter_by(name=item).one().description
    edit_super_link = '<a href="/catalog/{0}/{1}/edit">edit</a>'.format(category, item)
    output += edit_super_link
    delete_super_link = '<a href="/catalog/{0}/{1}/delete">delete</a>'.format(category, item)
    output += delete_super_link
    output += '</div>'

    if 'username' in login_session:
        output += '<a href="/gdisconnect">Disconnect</a>'
        output += '</br>'
    else:
        output += '<a href="/login">Connect</a>'
        output += '</br>'
    return output


@app.route('/catalog/new', methods=['GET', 'POST'])
def new_item():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        if request.form['name'] and request.form['category']:
            item_to_add = Item(name=request.form['name'], category=request.form['category'],
                               user=login_session['username'])
            session.add(item_to_add)
            session.commit()

            new_category = request.form['category']
            categories = session.query(Category).all()
            i = 0
            for category in categories:
                if category.name == new_category:
                    break
                else:
                    i += 1
            if i == len(categories):
                category = Category(name=request.form['category'], user=login_session['username'])
                session.add(category)
                session.commit()
        return redirect('/')
    else:
        return render_template('add_item.html')


@app.route('/catalog/<str:category>/<str:item>/edit', methods=['GET', 'POST'])
def edit_item(category, item):
    if 'username' not in login_session:
        return redirect('/login')

    item_to_modify = session.query(Item).filter_by(name=item).one()

    if item_to_modify.user.name != login_session['username']:
        response = make_response(json.dumps('Permission denied.'), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    if request.method == 'POST':
        if request.form['name']:
            item_to_modify.name = request.form['name']
        session.add(item_to_modify)
        session.commit()
        return redirect(url_for('show_item', category=category, item=item))
    else:
        return render_template('edit_item.html', category=category, item=item_to_modify)


@app.route('/catalog/<str:category>/<str:item>/delete')
def delete_item(category, item):
    if 'username' not in login_session:
        return redirect('/login')

    item_to_delete = session.query(Item).filter_by(name=item).one()

    if item_to_delete.user_id != login_session['user_id']:
        response = make_response(json.dumps('Permission denied.'), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    session.delete(item_to_delete)
    session.commit()
    return redirect('/catalog/%s/items' % category)


@app.route('/catalog.json')
def json_endpoint():
    categories = session.query(Category).all()
    return jsonify(Categories=[category.serialize for category in categories])


@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dump('Failed to upgrade the authorization code.', 401))
        response.headers['Content-Type'] = 'application_code'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print
        "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print
        'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print
    'In gdisconnect access token is %s', access_token
    print
    'User name is: '
    print
    login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print
    'result is '
    print
    result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def create_user(login_session_param):
    new_user = User(name=login_session_param['username'], email=login_session_param[
        'email'], picture=login_session_param['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session_param['email']).one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None



if __name__ == '__main__':
    app.secret_key = 'secret key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
