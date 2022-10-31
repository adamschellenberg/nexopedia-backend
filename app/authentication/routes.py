from sqlalchemy import null
from forms import UserLoginForm
from models import User, db, check_password_hash
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify

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

@auth.route('/avatar', methods = ['GET', 'POST'])
def get_avatar():
    token = request.json['token']
    print(token)
    if request.method == 'POST' and token is not None:
        logged_user = User.query.filter(User.token == token).first()
        if logged_user:
            response = {
                'avatar': logged_user.avatar
            }
            flash('You have fetched the avatar')
            return jsonify(response)
        else:
            response = {
                'message': 'Well this is awkward'
            }
            flash ('Something went wrong')
            return jsonify(response)
    return response

@auth.route('/avatar/update', methods = ['POST', 'PUT'])
def update_avatar():
    avatar = request.json['avatar']
    token = request.json['token']
    print(f'passing in avatar: {avatar}')
    try:
        if request.method == 'POST' and avatar is not None:
            logged_user = User.query.filter(User.token == token).first()
            if logged_user:
                logged_user.avatar = avatar
                db.session.commit()
                response = {
                    'message': f'You have updated your avatar to {avatar}',
                    'userAvatar': logged_user.avatar
                }
                return jsonify(response)
        else:
            response = {
                'message': 'You did not update your avatar'
            }
            return jsonify(response)
    except:
        raise Exception ('uh oh! Something went wrong!')