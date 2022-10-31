import json
from flask import Blueprint, request, jsonify, render_template
from helpers import token_required
from models import db, User

api = Blueprint('api', __name__, url_prefix='/api')

@api.route('/avatar', methods = ['GET'])
@token_required
def get_avatar(current_user_token):
    print(current_user_token.avatar)
    try:
        if request.method == 'GET':
            avatar = current_user_token.avatar
            response = {
                'avatar': avatar
            }
            return jsonify(response)
        else:
            response = {
                'message': 'Unable to fetch avatar'
            }
            return jsonify(response)
    except:
        raise Exception ('Could not get avatar data')

@api.route('/avatar/update', methods = ['POST', 'PUT'])
def update_avatar():
    avatar = request.json['avatar']
    print(f'test')
    try:
        if request.method == 'POST' and avatar is not None:
            User.avatar = avatar
            db.session.commit()
            response = {
                'message': f'You have updated your avatar to {avatar}',
                'userAvatar': User.avatar
            }
            return jsonify(response)
        else:
            response = {
                'message': 'You did not update your avatar'
            }
            return jsonify(response)
    except:
        raise Exception ('uh oh! Something went wrong!')