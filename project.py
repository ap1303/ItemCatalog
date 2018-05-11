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
engine = create_engine('sqlite:///categorywithusers.db?check_same_thread=False')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/<access_token>')
@app.route('/', defaults={'access_token':''})
def home_page(access_token):
    output = ''

    # display the categories as hyperlinks to their respective item lists
    output += 'categories'
    output += '</br>'
    categories = session.query(Category).all()
    for cat in categories:
        output += '<a href="/catalog/{0}/items/{1}">{2}</a>'.format(cat.name, access_token, cat.name)
        output += '</br>'

    if 'username' in login_session:  # user is logged in
        output += '<a href="catalog/new/{0}">Add Item</a>'.format(access_token)
        output += '</br>'
        output += '<a href="/gdisconnect">Disconnect</a>'
        output += '</br>'
    else:  # user is not logged in
        output += '<a href="/login">Connect</a>'
        output += '</br>'

    # hyperlink to the JSON Endpoint
    output += '<a href="/catalog.json">JSON</a>'

    return output


@app.route('/catalog/<category>/items/<access_token>')
@app.route('/catalog/<category>/items', defaults={'access_token':''})
def show_items(category, access_token):
    # Retrieve items for category and display them as hyperlinks to their respective pages
    cat = session.query(Category).filter_by(name=category).one()
    items = session.query(Item).filter_by(category=cat).all()
    output = ''
    for item in items:
        output += '<a href="/catalog/{0}/{1}/{2}">{3}</a>'.format(category, item.name, access_token, item.name)
        output += '</br>'

    if 'username' in login_session: # user is logged in
        output += '<a href="/gdisconnect">Disconnect</a>'
        output += '</br>'
    else:  # user is not logged in
        output += '<a href="/login">Connect</a>'
        output += '</br>'
    return output


@app.route('/catalog/<category>/<item>/<access_token>')
@app.route('/catalog/<category>/<item>', defaults={'access_token':''})
def show_item(category, item, access_token):
    # display item as its name, and add hyperlinks to edit, delete it
    output = '<div>{0}'.format(item)
    output += '</br>'
    edit_super_link = '<a href="/catalog/{0}/{1}/edit/{2}">edit</a>'.format(category, item, access_token)
    output += edit_super_link
    output += '</br>'
    delete_super_link = '<a href="/catalog/{0}/{1}/delete/{2}">delete</a>'.format(category, item, access_token)
    output += delete_super_link
    output += '</br>'
    output += '</div>'

    if 'username' in login_session:  #user logged in
        output += '<a href="/gdisconnect">Disconnect</a>'
        output += '</br>'
    else:  # user not logged in
        output += '<a href="/login">Connect</a>'
        output += '</br>'

    return output


@app.route('/catalog.json')
def json_endpoint():
    users = session.query(User).all()
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return jsonify(Users=[user.serialize for user in users], Categories=[category.serialize for category in categories], Items=[item.serialize for item in items])


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


def refresh():
    json_data = open('client_secrets.json')
    client_secrets = json.load(json_data)
    client_id = client_secrets['web']['client_id']
    client_secret = client_secrets['web']['client_secret']
    refresh_url = 'https://www.googleapis.com/oauth2/v4/token?refresh_token={0}&client_id={1}client_secret={2}&grant_type=refresh_token'.format(login_session['refresh_token'], client_id, client_secret)
    request = httplib2.Http().request(refresh_url, 'POST')
    result = json.loads(request[1])
    request_info = request[0]
    if request_info['status'] == '200':
        login_session['access_token'] = result['access_token']
        return ('200', login_session['access_token'])
    else:
        return (request_info['status'], 'Failed to obtain access token')


def check_access_token(access_token):
    if access_token != login_session['access_token']:
        return redirect('/login')
    else:
        refresh_tuple = refresh()
        if refresh_tuple[0] == '200':
            login_session['access_token'] = refresh_tuple[1]
            return None
        else:
            return redirect('/login')


@app.route('/catalog/new/<access_token>', methods=['GET', 'POST'])
def add_item(access_token):
    if 'username' not in login_session:  # user not logged in
        return redirect('/login')

    result = check_access_token(access_token)
    if result != None:
        return result

    if request.method == 'POST': # if the method is triggered by clicking the edit button on edit_item.html
        if request.form['name'] and request.form['category']:  # if both data fields are complete
            # check for existence of current user in database and if not, add current user to it
            users = session.query(User).all()
            user = User(name=login_session['username'], email=login_session['email'])
            existing = False
            for usr in users:
                if usr.name == user.name:
                    existing = True
                    break
            if not existing:
                session.add(user)
                session.commit()
            else:
                user = session.query(User).filter_by(name=login_session['username']).one()

            # check for existence of given category in database and if not, add given category to it
            categories = session.query(Category).all()
            cat = Category(name=request.form['category'], user=user)
            existing = False
            for category in categories:
                if category.name == cat.name:
                    existing = True
                    break
            if not existing:
                session.add(user)
                session.commit()
            else:
                cat = session.query(Category).filter_by(name=request.form['category']).one()

            # add the item to database
            item_to_add = Item(name=request.form['name'], category=cat,
                               user=user)
            session.add(item_to_add)
            session.commit()

        return redirect('/{0}'.format(login_session['access_token']))
    else:  # if the method is triggered by clicking the Add button on the home page
        return render_template('add_item.html')


@app.route('/catalog/<category>/<item>/edit/<access_token>', methods=['GET', 'POST'])
def edit_item(category, item, access_token):
    if 'username' not in login_session:
        return redirect('/login')

    result = check_access_token()
    if result != None:
        return result

    item_to_modify = session.query(Item).filter_by(name=item).one()

    if item_to_modify.user.id != login_session['user_id']:
        response = make_response(json.dumps('Permission denied.'), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    if request.method == 'POST':
        if request.form['name']:
            item_to_modify.name = request.form['name']
        session.add(item_to_modify)
        session.commit()
        return redirect(url_for('show_item', category=category, item=item_to_modify.name))
    else:
        return render_template('edit_item.html', category=category, item=item_to_modify)


@app.route('/catalog/<category>/<item>/delete/<access_token>')
def delete_item(category, item):
    if 'username' not in login_session:
        return redirect('/login')

    result = check_access_token()
    if result != None:
        return result

    item_to_delete = session.query(Item).filter_by(name=item).one()

    if item_to_delete.user_id != login_session['user_id']:
        response = make_response(json.dumps('Permission denied.'), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    session.delete(item_to_delete)
    session.commit()
    return redirect('/catalog/%s/items' % category)


@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect(access_token):
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
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['refresh_token'] = credentials.refresh_token
    login_session['gplus_id'] = gplus_id

    user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(user_info_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    return redirect('/{0}'.format(login_session['access_token']))


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
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
        json_string = 'Failed to revoke token {0} for given user with status code {1}'.format(login_session['access_token'], result['status'])
        response = make_response(json.dumps(json_string, 400))
        response.headers['Content-Type'] = 'application/json'
        return response
        

if __name__ == '__main__':
    app.secret_key = 'secret key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
