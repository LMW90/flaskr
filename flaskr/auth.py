# a blueprint for register, log in, log out views

import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


# register view
@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        # take values from user input
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        # validate if fields were submitted
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        # in both fiels were submitted try to save them to database
        if error is None:
            try:
                db.execute(
                    'INSERT INTO user (username, password) VALUES (?, ?)',
                    (username, generate_password_hash(password)),
                )
                db.commit()
            # if entry already exists in a db
            except db.IntegrityError:
                error = f'User {username} is already registered.'
            # redirect user to login page
            else:
                return redirect(url_for('auth.login'))

        # display error to a user flash stores message for retrieval
        flash(error)

    return render_template('auth/register.html')


# view for login page
@bp.route('/login', methods=('GET', 'POST')) 
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        # query user and store in a variable, fetchone() returns one row if no matches returns None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        # validate username and password
        if user is None:
            error = 'Incorrect username.'
        # hashes submitted password and compares to hash stored in database
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        # session is dictionary storing data across multiple requests
        #  after successful login it will store user's id in a new session
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index))'))

        flash(error)

    return render_template('auth/login.html')

# decorator registers function that runs before view functions
# the function checks for user id in session and saves user data from database in g, if not found sets user in g to None
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


# removes user from session, load_logged_in_user won't be able to load user on subsequent requests
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# decorator to wrap any view function into view that checks if there is a logged user data in g
#  if there is none, redirects to auth.login
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        
        return view(**kwargs)

    return wrapped_view

