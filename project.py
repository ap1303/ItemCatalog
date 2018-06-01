from flask import Flask, render_template, request, flash, jsonify, url_for, redirect, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from sqlalchemy.orm.exc import NoResultFound
from datetime import datetime
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
activation_time = datetime.now()


@app.route('/catalog/homepage/<access_token>')
@app.route('/catalog/homepage', defaults={'access_token':''})
def home_page(access_token):
    timedelta = datetime.now() - activation_time
    if timedelta.seconds > 3600:
        clean_session_data()

    categories = session.query(Category).all()
    return render_template('homepage.html', categories=categories, access_token=access_token)


@app.route('/catalog/<category>/items/<access_token>')
@app.route('/catalog/<category>/items/', defaults={'access_token':''})
def show_items(category, access_token):
    timedelta = datetime.now() - activation_time
    if timedelta.seconds > 3600:
        clean_session_data()

    result = check_access_token(access_token)
    if result is not None and result != 'No access token':
        return redirect('/login')

    try:
        cat = session.query(Category).filter_by(name=category).one()
    except NoResultFound:
        response = make_response(json.dumps('No such category. '), 404)
        response.headers['Content-Type'] = 'application/json'
        return response
    items = session.query(Item).filter_by(category=cat).all()

    return render_template('show_items.html', category=category, items=items, access_token=access_token)


@app.route('/catalog/<category>/new/<access_token>', methods=['POST', 'GET'])
def add_item_to_category(category, access_token):
    timedelta = datetime.now() - activation_time
    if timedelta.seconds > 3600:
        clean_session_data()

    result = check_access_token(access_token)
    if result is not None:
        return redirect('/login')

    if request.method == 'POST': # if the method is triggered by clicking the add button
        if request.form['name'] and request.form['description']: # if data is complete
            # add the item to database
            user = session.query(User).filter_by(name=login_session[access_token]['username']).one()
            try:
                cat = session.query(Category).filter_by(name=category).one()
            except NoResultFound:
                response = make_response(json.dumps('No such category'), 404)
                response.headers['Content-Type'] = 'application/json'
                return response
            item_to_add = Item(name=request.form['name'], description=request.form['description'], category=cat, user=user)
            names = [item.name for item in session.query(Item).all()]
            if request.form['name'] not in names:
                session.add(item_to_add)
                session.commit()
            else:
                return render_template('add_item_failure.html', category=category, access_token=access_token)
        return redirect('/catalog/{0}/items/{1}'.format(category, access_token))
    else:  # if the method is triggered by clicking the Add button on the home page
        return render_template('add_item_to_category.html', category=category, access_token=access_token)


@app.route('/catalog/<category>/<item>/<access_token>')
@app.route('/catalog/<category>/<item>/', defaults={'access_token':''})
def show_item(category, item, access_token):
    timedelta = datetime.now() - activation_time
    if timedelta.seconds > 3600:
        clean_session_data()

    # display item as its name, and add hyperlinks to edit, delete it
    result = check_access_token(access_token)
    if result is not None and result != 'No access_token':
        return redirect('/login')

    try:
        item_to_show = session.query(Item).filter_by(name=item).one()
    except NoResultFound:
        response = make_response(json.dumps('No such item. '), 404)
        response.headers['Content-Type'] = 'application/json'
        return response

    if len(access_token) == 0:
        current_user = ''
    else:
        current_user = login_session[access_token]['username']

    return render_template('show_item.html', current_user=current_user, item_username=item_to_show.user.name, category=category, item=item, description=item_to_show.description, access_token=access_token)


@app.route('/catalog.json')
def json_endpoint():
    timedelta = datetime.now() - activation_time
    if timedelta.seconds > 3600:
        clean_session_data()

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
    except NoResultFound:
        return None


def check_access_token(access_token):
    if len(access_token) == 0:
       return 'No access token'
    elif access_token not in login_session:
       return 'not logged in'
    else:
        timedelta = datetime.now() - login_session[access_token]['last_click']
        if timedelta.seconds > 1800:
            return 'Session timeout'
        else:
            return None


def clean_session_data():
    keys = login_session.keys()
    for user in keys:
        last_click = login_session[user]['last_click']
        timedelta = datetime.now() - last_click
        if timedelta.seconds > 1800:
            del login_session[user]




@app.route('/catalog/new/<access_token>', methods=['GET', 'POST'])
def add_item(access_token):
    timedelta = datetime.now() - activation_time
    if timedelta.seconds > 3600:
        clean_session_data()

    result = check_access_token(access_token)
    if result is not None:
        return redirect('/login')

    if request.method == 'POST': # if the method is triggered by clicking the edit button on edit_item.html
        if request.form['name'] and request.form['category'] and request.form['description']:  # if both data fields are complete
            # check for existence of current user in database and if not, add current user to it
            usernames = [item.name for item in session.query(User).all()]
            user = User(name=login_session[access_token]['username'], email=login_session[access_token]['email'])
            if user.name not in usernames:
                session.add(user)
                session.commit()
            else:
                user = session.query(User).filter_by(name=login_session[access_token]['username']).one()

            # check for existence of given category in database and if not, add given category to it
            categories = [item.name for item in session.query(Category).all()]
            cat = Category(name=request.form['category'], user=user)
            if cat.name not in categories:
                session.add(cat)
                session.commit()
            else:
                cat = session.query(Category).filter_by(name=request.form['category']).one()

            # add the item to database
            item_to_add = Item(name=request.form['name'], description=request.form['description'], category=cat,
                               user=user)
            names = [item.name for item in session.query(Item).all()]
            if request.form['name'] not in names:
                session.add(item_to_add)
                session.commit()
            else:
                return render_template('add_item_failure.html', access_token=access_token)
        return redirect('/catalog/homepage/{0}'.format(access_token))
    else:  # if the method is triggered by clicking the Add button on the home page
        return render_template('add_item.html', access_token=access_token)


@app.route('/catalog/<category>/<item>/edit/<access_token>', methods=['GET', 'POST'])
def edit_item(category, item, access_token):
    timedelta = datetime.now() - activation_time
    if timedelta.seconds > 3600:
        clean_session_data()

    result = check_access_token(access_token)
    if result is not None:
        return redirect('/login')

    item_to_modify = session.query(Item).filter_by(name=item).one()

    if item_to_modify.user.id != get_user_id(login_session[access_token]['email']):
        response = make_response(json.dumps('Permission denied.'), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    if request.method == 'POST':
        if request.form['name'] and request.form['category'] and request.form['description']:
            item_to_modify.name = request.form['name']

            try:
                would_be_category = session.query(Category).filter_by(name=request.form['category']).one()
                item_to_modify.category = would_be_category
            except NoResultFound:
                usernames = [item.name for item in session.query(User).all()]
                user = User(name=login_session[access_token]['username'], email=login_session[access_token]['email'])
                if user.name not in usernames:
                    session.add(user)
                    session.commit()
                else:
                    user = session.query(User).filter_by(name=login_session[access_token]['username']).one()
                cat = Category(name=request.form['category'], user=user)
                item_to_modify.category = cat

                item_to_modify.description = request.form['description']
        session.add(item_to_modify)
        session.commit()
        return redirect(url_for('show_item', category=item_to_modify.category.name, item=item_to_modify.name, access_token=access_token))
    else:
        return render_template('edit_item.html', category=category, item=item_to_modify, access_token=access_token)


@app.route('/catalog/<category>/<item>/delete/<access_token>', methods=['GET', 'POST'])
def delete_item(category, item, access_token):
    timedelta = datetime.now() - activation_time
    if timedelta.seconds > 3600:
        clean_session_data()

    result = check_access_token(access_token)
    if result is not None:
        return redirect('/login')

    if request.method == 'POST':
        try:
            item_to_delete = session.query(Item).filter_by(name=item).one()
            category_instance = item_to_delete.category
        except NoResultFound:
           print('No rows found')

        if item_to_delete.user_id != get_user_id(login_session[access_token]['email']):
            response = make_response(json.dumps('Permission denied.'), 403)
            response.headers['Content-Type'] = 'application/json'
            return response

        session.delete(item_to_delete)
        session.commit()

        items = [item.name for item in session.query(Item).filter_by(category=category_instance).all()]
        if len(items) == 0:
            session.delete(session.query(Category).filter_by(name=category).one())
            session.commit()
            return redirect('/catalog/homepage/{0}'.format(access_token))
        return redirect('/catalog/{0}/items/{1}'.format(category, access_token))
    else:
        return render_template('delete_item.html', category=category, item=item, access_token=access_token)




@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    state = login_session['state']
    del login_session['state']

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
    refresh_token = credentials.refresh_token
    print('access: {0}, refresh: {1}'.format(access_token, refresh_token))
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

    if access_token in login_session and gplus_id == login_session[access_token][gplus_id]:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    dict = {}
    dict['last_click'] = datetime.now()
    dict['state'] = state
    dict['refresh_token'] = refresh_token
    dict['gplus_id'] = gplus_id

    user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(user_info_url, params=params)

    data = answer.json()

    dict['username'] = data['name']
    dict['picture'] = data['picture']
    dict['email'] = data['email']

    login_session[access_token] = dict

    user = User(name=data['name'], email=data['email'])
    session.add(user)
    session.commit()

    return redirect('/catalog/homepage/{0}'.format(access_token))


@app.route('/logout/<access_token>')
def show_logout(access_token):
    return render_template('logout.html')


@app.route('/gdisconnect/<access_token>')
def gdisconnect(access_token):
    if len(access_token) == 0:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token={0}'.format(access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200' or result['status'] == '400':
        del login_session[access_token]
        return redirect('/catalog/homepage')
    else:
        json_string = 'Failed to revoke token {0} for given user with status code {1}'.format(access_token, result['status'])
        response = make_response(json.dumps(json_string, 400))
        response.headers['Content-Type'] = 'application/json'
        return response


if __name__ == '__main__':
    app.secret_key = 'secret key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
