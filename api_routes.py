from flask_restful import Resource, reqparse, fields, marshal_with
from flask import abort
from app import api, db
from models import User
from werkzeug.security import generate_password_hash, check_password_hash

# Define output fields to ensure consistent response structure
user_fields = {
    'userid': fields.Integer,
    'username': fields.String,
    'usertype': fields.String,
    'name': fields.String,
    'email': fields.String,
    'profile_pic': fields.String
}

class UserAPI(Resource):
    @marshal_with(user_fields)
    def get(self, username):
        user = User.query.filter_by(username=username).first_or_404(description='User not found')
        return user
        
    def delete(self, username):
        user = User.query.filter_by(username=username).first()
        if not user:
            abort(404, description='User not found')
        
        db.session.delete(user)
        db.session.commit()
        
        return {'message': 'User deleted'}, 204

class UserListAPI(Resource):
    @marshal_with(user_fields)
    def get(self):
        users = User.query.all()
        return users
    
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('firstname', type=str, required=True, help='First name is required')
        parser.add_argument('lastname', type=str, required=True, help='Last name is required')
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        parser.add_argument('usertype', type=str, required=True, help='Usertype is required')
        parser.add_argument('email', type=str, required=True, help='Email is required')
        parser.add_argument('profile_pic', type=str)
        
        args = parser.parse_args()
        
        if User.query.filter_by(username=args['username']).first():
            abort(400, description='Username already exists')
        
        if User.query.filter_by(email=args['email']).first():
            abort(400, description='Email already exists')
        
        name = f"{args['firstname']} {args['lastname']}"
        passhash = generate_password_hash(args['password'])
        new_user = User(
            username=args['username'],
            passhash=passhash,
            usertype=args['usertype'],
            name=name,
            email=args['email'],
            profile_pic=args.get('profile_pic', 'default_profile_pic.jpg')
        )
        db.session.add(new_user)
        db.session.commit()
        
        return {'message': 'User created'}, 201

api.add_resource(UserAPI, '/api/users/<string:username>')
api.add_resource(UserListAPI, '/api/users')