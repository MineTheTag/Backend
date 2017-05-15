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
from datetime import *
from math import sin, cos, sqrt, atan2, radians


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
    blocked = db.Column(db.DateTime, default=datetime.now())

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)
        print(self.password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

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

    def is_user_blocked(self):
        if self.blocked > datetime.now():
            return True
        else:
            return False

    def block_user(self, minuts=1):
        self.blocked = datetime.now() + timedelta(minutes=minuts)
        db.session.commit()

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
        user = User.query.filter_by(name=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

class Mine(db.Model):
    __tablename__ = 'mine'
    id = db.Column(db.Integer, primary_key=True)
    posX = db.Column(db.Float)
    posY = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User',
        backref=db.backref('mines', lazy='dynamic'))

def add_mine(x, y, user):
	mine = Mine(posX = x, posY = y, user = user)
	db.session.add(mine)
	db.session.commit()

class Tag(db.Model):
     __tablename__ = 'tag'
     id = db.Column(db.Integer, primary_key=True)
     posX = db.Column(db.Float)
     posY = db.Column(db.Float)
     user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
     user = db.relationship('User',
         backref=db.backref('tags', lazy='dynamic'))

def add_tag(x, y, user):
	tag = Tag(posX = x, posY = y, user = user)
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
        #abort(403) #missing arguments
        return json.dumps({"result": "missing arguments"})
    if User.query.filter_by(name=username).first() is not None:#TODO: canviar per funció user_exist a
        #abort(400) #existing user
        return json.dumps({"result": "existing user"})

    add_user(username, password)
    return json.dumps({"result": "success"})

# Implementació de verificació de passwords o tokens per accedir a dades d'usuari
@auth.verify_password
def verify_password(username_or_token, password):
    #intentem autenticar amb token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # intentem autenticar amb username/password
        user = User.query.filter_by(name = username_or_token).first()
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

# Funció de test. TODO: Eliminar-la al final
@app.route('/test')
@auth.login_required
def user_test():
    return json.dumps("Hello user %s" % g.user.name )


##################################
######## GESTIÓ DE MINES #########
##################################

@app.route('/api/mines/new', methods = ['POST'])
@auth.login_required
def new_mine():
    x = request.json.get('x_pos')
    y = request.json.get('y_pos')
    add_mine(x,y,g.user)
    return json.dumps({"result":"OK"})

def delete_mine(mine):
    db.session.delete(mine)
    db.session.commit()

def explosio(posX, posY):
    mine = Mine.query.all()
    exploded_mines = []
    for i in mine:
        explota = compare(posX, posY,i.posX, i.posY)
        if (explota == True):
            if (g.user.id != i.user_id):
                exploded_mines.append((i.posX,i.posY))
                delete_mine(i)
    return exploded_mines

@app.route('/api/mines/check/explosion', methods = ['POST'])
@auth.login_required
def check_explosion():
    x = request.json.get('x_pos')
    y = request.json.get('y_pos')
    if not g.user.is_user_blocked():
        exploded_mines = explosio(x, y)
        if exploded_mines:
            g.user.block_user()
            return json.dumps({"result":"Booom", "exploded_mines" : exploded_mines})
        else:
            return json.dumps({"result":"Keep calm"})
    else:
        return json.dumps({"result":"Keep calm"})

#Retorna cert si explota o fals si no explota
def compare(posX, posY, mineX, mineY, radi=15):
# approximate radius of earth in m
    R = 6373000.0
    lat1 = radians(posX)
    lon1 = radians(posY)
    lat2 = radians(mineX)
    lon2 = radians(mineY)
    lon = lon2 - lon1
    lat = lat2 - lat1
    a = sin(lat / 2)**2 + cos(lat1) * cos(lat2) * sin(lon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = R * c
    print("La distancia es: %02d metres") % (distance)
    if (distance <= radi):
        return True
    else:
        return False

# Retorna totes les mines d'un usuari
@app.route('/api/mines/get', methods = ['POST'])
@auth.login_required
def get_mines():
    mines = Mine.query.filter_by(user_id=g.user.id).all()
    mines_ret =  [(mine.posX,mine.posY) for mine in mines]
    return json.dumps(mines_ret)

# Retorna totes les mines dels altres usuaris
@app.route('/api/admin/mines/getdiff', methods = ['POST'])
@auth.login_required
def admin_get_other_mines():
    mines = Mine.query.filter(user_id != g.user.id).all()
    mines_ret =  [(mine.posX,mine.posY) for mine in mines]
    return json.dumps(mines_ret)


##################################
#######  GESTIÓ DE TAGS  #########
##################################

@app.route('/api/tags/new', methods=['POST'])
@auth.login_required
def new_tag():
    x = request.json.get('x_pos')
    y = request.json.get('y_pos')
    add_tag(x, y, g.user)
    return json.dumps({"result": "OK"})

# Retorna tots els tags
@app.route('/api/tags/get', methods=['POST'])
@auth.login_required
def get_tags():
    tags = Tag.query.all()
    tags_ret = [{'x_pos': tag.posX, 'y_pos': tag.posY, 'user': tag.user_id}
                for tag in tags]
    return json.dumps(tags_ret)


# Main
if __name__ == '__main__':
    #Create the tables
    db.create_all()
    app.run(host='0.0.0.0',debug=True)
