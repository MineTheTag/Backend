#!/usr/bin/env python

from flask import Flask, g
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
import json
#imports geoalchemy
#from generacioBD import taulesBD

app = Flask(__name__)

##################################
######## GESTIÓ D'USUARIS ########
##################################

auth = HTTPBasicAuth()

# User registration
@app.route('/api/user/registration', methods = ['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')

    if username is None or password is None:
        abort(403) #missing arguments
        #return json.dumps({'missing arguments'})
    if User.query.filter_by(username=username).first() is not None:
        abort(400) #existing user
        #return json.dumps({'existing user'})
    user = User(username = username)
    user.hash_password(password) #TODO: Implementar-ho a script generació BD
    db.session.add(user)
    db.session.commit()
    return json.dumps({'success'})

# Implementació de verificació de passwords o tokens per accedir a dades d'usuari
@auth.verify_password
def verify_password(username_or_token, passwprd):
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

@app.route('/')
def hello_world():
    return 'Hello, World!'


if __name__ == '__main__':
    app.run(host='0.0.0.0')
