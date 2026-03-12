#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

# schemas convert SQLAlchemy objects -> JSON responses
user_schema = UserSchema()
recipe_schema = RecipeSchema()
recipes_schema = RecipeSchema(many=True)


class Signup(Resource):

    def post(self):

        # grab incoming JSON from the frontend
        data = request.get_json()

        try:

            # create a new user instance
            user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )

            # triggers bcrypt hashing through hybrid_property setter
            user.password_hash = data.get('password')

            # save user to database
            db.session.add(user)
            db.session.commit()

            # store their id in the session cookie so they stay logged in
            session['user_id'] = user.id

            # return serialized user JSON
            return user_schema.dump(user), 201

        except (ValueError, IntegrityError) as e:

            # rollback prevents broken transactions
            db.session.rollback()

            # return validation errors
            return {"errors": [str(e)]}, 422


class CheckSession(Resource):

    def get(self):

        # check if user_id exists in session cookie
        user_id = session.get('user_id')

        if user_id:

            # find user from DB
            user = User.query.filter_by(id=user_id).first()

            if user:
                return user_schema.dump(user), 200

        return {"error": "Unauthorized"}, 401


class Login(Resource):

    def post(self):

        data = request.get_json()

        # look up user by username
        user = User.query.filter_by(username=data.get('username')).first()

        # verify password using bcrypt
        if user and user.authenticate(data.get('password')):

            # create session cookie
            session['user_id'] = user.id

            return user_schema.dump(user), 200

        return {"error": "Unauthorized"}, 401


class Logout(Resource):

    def delete(self):

        # if session exists remove user_id
        if session.get('user_id'):

            session.pop('user_id', None)

            # 204 = success but no response body
            return '', 204

        return {"error": "Unauthorized"}, 401


class RecipeIndex(Resource):

    def get(self):

        # user must be logged in to view recipes
        if not session.get('user_id'):
            return {"error": "Unauthorized"}, 401

        recipes = Recipe.query.all()

        # return serialized recipe list
        return recipes_schema.dump(recipes), 200


    def post(self):

        # user must be logged in to create recipes
        user_id = session.get('user_id')

        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.filter_by(id=user_id).first()

        data = request.get_json()

        try:

            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete')
            )

            # associate recipe with logged in user
            recipe.user = user

            db.session.add(recipe)
            db.session.commit()

            return recipe_schema.dump(recipe), 201

        except (ValueError, IntegrityError) as e:

            db.session.rollback()

            return {"errors": [str(e)]}, 422


api.add_resource(Signup, '/signup')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(RecipeIndex, '/recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)