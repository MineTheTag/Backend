#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from flask import Flask, g, request, abort
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
import json
from flask_sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)


##################################
######## INICIALITZACIO ##########
##################################


try:
	db_user = os.environ['MTTG_DB_USER']
except:
	db_user = "mttg"
try:
	db_password = os.environ['MTTG_DB_PASSWORD'] or "password"
except:
	db_password= "password"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clau secreta de prova'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://%s:%s@db/mttg' %(db_user,db_password)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db' #Per test
#app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
auth = HTTPBasicAuth()

@app.route('/')
def hello_world():
    return 'Hello, World!'


#######################################
######## DEFINICIÓ DE TAULES ##########
#######################################

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80),unique=True)
    password = db.Column(db.String(120))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        #s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
	s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'id': self.id})


    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user

def add_user(username, password):
	user = User(name = username)
    	user.hash_password(password)
	db.session.add(user)
	db.session.commit()

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

class Mine(db.Model):
     __tablename__ = 'mine'
     id = db.Column(db.Integer, primary_key=True)
     posX = db.Column(db.Float)
     posY = db.Column(db.Float)

def add_mine(x, y):
	mine = Mine(posX = x, posY = y)
	db.session.add(mine)
	db.session.commit()

class Tag(db.Model):
     __tablename__ = 'tag'
     id = db.Column(db.Integer, primary_key=True)
     posX = db.Column(db.Float)
     posY = db.Column(db.Float)

def add_tag(x, y):
	tag = Tag(posX = x, posY = y)
	db.session.add(tag)
	db.session.commit()

##################################
######## GESTIÓ D'USUARIS ########
##################################

# User registration
@app.route('/api/user/registration', methods = ['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if username is None or password is None:
        abort(403) #missing arguments
        #return json.dumps({'missing arguments'})
    if User.query.filter_by(name=username).first() is not None:#TODO: canviar per funció user_exist a
        abort(400) #existing user
        #return json.dumps({'existing user'})

    add_user(username, password)
    return json.dumps({'success'})

# Implementació de verificació de passwords o tokens per accedir a dades d'usuari
@auth.verify_password
def verify_password(username_or_token, password):
    #intentem autenticar amb token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # intentem autenticar amb username/password
        user = User.query.filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

# Per demanar un token
@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return json.dumps({ 'token': token.decode('ascii') })


##################################
######## GESTIÓ DE MINES #########
##################################


if __name__ == '__main__':
    #Create the tables
    db.create_all()
    app.run(host='0.0.0.0')
