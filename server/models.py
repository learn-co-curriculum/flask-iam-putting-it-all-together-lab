from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields

from config import db, bcrypt


class User(db.Model):

    __tablename__ = 'users'

    # primary key
    id = db.Column(db.Integer, primary_key=True)

    # username must exist and must be unique
    username = db.Column(db.String, nullable=False, unique=True)

    # stored bcrypt hash
    _password_hash = db.Column(db.String)

    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # relationship -> user has many recipes
    recipes = db.relationship('Recipe', back_populates='user')


    # prevents password hashes from ever being returned
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")


    # setter hashes plaintext password with bcrypt
    @password_hash.setter
    def password_hash(self, password):

        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))

        self._password_hash = password_hash.decode('utf-8')


    # compares plaintext password against stored hash
    def authenticate(self, password):

        return bcrypt.check_password_hash(
            self._password_hash,
            password.encode('utf-8')
        )


    # validate username exists
    @validates('username')
    def validate_username(self, key, username):

        if not username:
            raise ValueError("Username must be present")

        return username



class Recipe(db.Model):

    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String, nullable=False)

    instructions = db.Column(db.String, nullable=False)

    minutes_to_complete = db.Column(db.Integer)

    # foreign key to user table
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # relationship back to user
    user = db.relationship('User', back_populates='recipes')


    @validates('title')
    def validate_title(self, key, title):

        if not title:
            raise ValueError("Recipe title required")

        return title


    @validates('instructions')
    def validate_instructions(self, key, instructions):

        if not instructions:
            raise ValueError("Instructions required")

        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters")

        return instructions



class UserSchema(Schema):

    id = fields.Int()
    username = fields.Str()
    image_url = fields.Str()
    bio = fields.Str()


class RecipeSchema(Schema):

    id = fields.Int()
    title = fields.Str()
    instructions = fields.Str()
    minutes_to_complete = fields.Int()

    # nested user object
    user = fields.Nested(UserSchema)