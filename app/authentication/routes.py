from sqlalchemy import null
from forms import UserLoginForm
from models import User, db, check_password_hash
from flask import Blueprint, render_template, request, redirect, url_for, flash

from flask_login import login_user, logout_user, LoginManager, current_user, fresh_login_required

auth = Blueprint('auth', __name__, template_folder='auth_templates')

@auth.route('/signup', methods = ['GET', 'POST'])
def signup():
    email = request.json['email']
    password = request.json['password']
    print(f'email: {email}')
    print(f'password: {password}')
    try:
        if request.method == 'POST' and email is not None and password is not None:
            
            user = User(email, password = password)

            db.session.add(user)
            db.session.commit()

            response = {
                'text': f'You have successfully created a user account {email}',
                'success': True,
            }
            flash(f'You have successfully created a user account {email}', 'User-created')
            return response

    except:
        raise Exception('Invalid form data: Please check your form')
    return

@auth.route('/signin', methods=['GET', 'POST'])
def signin():
    email = request.json['email']
    password = request.json['password']
    try:
        if request.method == 'POST' and email is not None and password is not None:

            logged_user = User.query.filter(User.email == email).first()
            if logged_user and check_password_hash(logged_user.password, password):
                login_user(logged_user)
                response = {
                    'token': logged_user.token
                }
                flash('You have successfully logged in', 'auth-success')
                return response
            else:
                flash('You do not have access to this content.', 'auth-failed')
                return
    except:
        raise Exception('Invalid Form Data: Please check your form')
    return response

@auth.route('/logout')
def logout():
    logout_user()
    return