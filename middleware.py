from flask import session, jsonify
from functools import wraps
import dbutils
from flask import Flask, url_for, redirect, session, request, jsonify
import json

def read_config():
    f = open('secrets/config.json')
    return json.load(f)

conf = read_config()

def dev_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if conf.get("development", False) == True:
            user = dbutils.get_user_by_id(1)
            session["user"] = {"id": user.id, "first_name": user.first_name, "last_name": user.last_name, "email": user.email, "uuid": user.uuid}
            session.permanent = True
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = dict(session).get('user', None)
        if user:
            return f(*args, **kwargs)
        return jsonify({'message': 'You are currently not logged in!'}), 401
    return decorated_function

def upload_credentials(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = dict(session).get('user', None)
        if dbutils.is_admin(user["id"]) or dbutils.is_uploader(user["id"]):
            return f(*args, **kwargs)
        return jsonify({'message': 'You need to be admin or have permission to upload files.'}), 403
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = dict(session).get('user', None)
        if dbutils.is_admin(user["id"]) :
            return f(*args, **kwargs)
        return jsonify({'message': 'You need to be admin for this operation.'}), 403
    return decorated_function

def accesskey_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not "user" in session.keys():
            user_key = request.headers.get('x-api-key', None)
            if user_key:
                if not dbutils.key_valid(user_key):
                    return jsonify({'message': 'API key invalid or expired.'}), 403
                user = dbutils.get_key_user(user_key)
                session["user"] = {"id": user.id, "first_name": user.first_name, "last_name": user.last_name, "email": user.email, "uuid": user.uuid}
                session.permanent = True
        return f(*args, **kwargs)
    return decorated_function