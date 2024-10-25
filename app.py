from flask import Flask, url_for, redirect, session, request, jsonify, Response
import traceback
import json
import requests
import time
from apscheduler.schedulers.background import BackgroundScheduler

from authlib.integrations.flask_client import OAuth

from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from models import db, User, File, Collection, DownloadLog, Role, UserRole, Policy, RolePolicy, PolicyCollections, PolicyFiles, Accesskey
import dbutils
import s3utils

from middleware import login_required, upload_credentials, admin_required, accesskey_login, dev_login

from datetime import timedelta

from werkzeug.routing import BaseConverter
from flask_caching import Cache

from flask_swagger_ui import get_swaggerui_blueprint

class IntListConverter(BaseConverter):
    regex = r'\d+(?:,\d+)*,?'
    def to_python(self, value):
        return [int(x) for x in value.split(',')]
    def to_url(self, value):
        return ','.join(str(x) for x in value)

import logging
import sys
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

# Get the 'werkzeug' logger specifically
log = logging.getLogger('werkzeug')
log.setLevel(logging.DEBUG)

# Create a StreamHandler for stdout
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
log.addHandler(handler)

def read_config():
    f = open('secrets/config.json')
    return json.load(f)

app = Flask(__name__, 
        static_url_path='/api/static',
        static_folder='static',
        template_folder='templates')

cors = CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = "ffx#xkj$WWs2"
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)

app.url_map.converters['int_list'] = IntListConverter

cache = Cache(app, config={"CACHE_TYPE": "simple"})

conf = read_config()

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://"+conf["database"]["user"]+":"+conf["database"]["pass"]+"@"+conf["database"]["server"]+":"+conf["database"]["port"]+"/"+conf["database"]["name"]
app.config['SQLALCHEMY_POOL_SIZE'] = 40
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
app.app_context().push()

pool_size = db.engine.pool.size()
print(f"Current pool size: {pool_size}")

### swagger specific ###
SWAGGER_URL = '/api/docs'
API_URL = '/api/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Datacrossways",
        'displayHeader': False  # Hide the SmartBear header
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)
### end swagger specific ###

#oauth config
oauth = OAuth(app)

if "oauth" in conf and "google" in conf["oauth"]:
    oauth.register(
        name = "google",
        client_id = conf["oauth"]["google"]["client_id"],
        client_secret = conf["oauth"]["google"]["client_secret"],
        access_token_url = conf["oauth"]["google"]["token_uri"],
        authorize_url = conf["oauth"]["google"]["auth_uri"],
        api_base_url = 'https://www.googleapis.com/oauth2/v1/',
        client_kwargs={'scope': 'openid email profile'}
    )

if "oauth" in conf and "orcid" in conf["oauth"]:
    oauth.register(
        name = "orcid",
        client_id = conf["oauth"]["orcid"]["client_id"],
        client_secret = conf["oauth"]["orcid"]["client_secret"],
        base_url='https://pub.orcid.org/v3.0/',
        request_token_url=None,
        access_token_url='https://orcid.org/oauth/token',
        authorize_url='https://orcid.org/oauth/authorize',
        client_kwargs={'scope': 'openid email profile'}
    )

def search_checksum():
    with app.app_context():
        try:
            dbutils.file_checksum_status()
        except Exception as e:
            traceback.print_exc()


scheduler = BackgroundScheduler()
scheduler.add_job(func=search_checksum, trigger="interval", seconds=15)
scheduler.start()

@app.route('/api/stats', methods = ["GET"])
@cache.cached(timeout=60)
def get_stats():
    try:
        stats = dbutils.get_stats()
        return jsonify(stats), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when retrieving stats"), 500

# User API endpoints
# - user [GET] -> list all users
# - user [POST]-> create a new user
# - user [PATCH] -> update user
# - user [DELETE] -> delete user
@app.route('/api/user', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
@admin_required
def get_user():
    try:
        users = dbutils.list_users()
        return jsonify(users=users), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when listing users"), 500

@app.route('/api/user/file', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_user_files():
    try:
        offset = request.args.get("offset", default=0)
        limit = request.args.get("limit", default=20)
        files, file_count = dbutils.list_user_files(session["user"]["id"], offset, limit)
        return jsonify({"message": "files listed successfully", "files": files, "total": file_count}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when listing files"), 500

@app.route('/api/user/storage', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_user_storage():
    try:
        st = time.time()
        file_quota_used, file_quota_available, file_quota = dbutils.list_user_quota(session["user"]["id"])
        print(time.time() - st)
        return jsonify({"file_quota_used": file_quota_used, "file_quota": file_quota, "file_quota_available": file_quota_available, "info": "quota in MB"}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when listing file quota"), 500

@app.route('/api/user/collection', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_user_collections():
    try:
        offset = request.args.get("offset", default=0)
        limit = request.args.get("limit", default=1000)
        files, file_count = dbutils.list_user_collections(session["user"]["id"], offset, limit)
        return jsonify({"message": "files listed successfully", "collections": files, "offset": offset, "limit": limit, "total": file_count}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when listing collections"), 500

@app.route('/api/user', methods = ["POST"])
@accesskey_login
@dev_login
@login_required
@admin_required
def post_user():
    try:
        data = request.get_json()
        user = dbutils.create_user(data)
        return jsonify({"message": "user created successfully", "user": user}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when creating user"), 500

@app.route('/api/user/bulk', methods = ["POST"])
@accesskey_login
@dev_login
@login_required
@admin_required
def post_user_bulk():
    try:
        data = request.get_json()
        users, failed_users = dbutils.create_users_bulk(data)
        if len(users) > 0 & len(failed_users) == 0:
            message = "all users created successfully"
        elif len(users) > 0 & len(failed_users) > 0:
            message = "some users created successfully, but some failed"
        else:
            message = "all users failed"
        return jsonify({"message": message, "users": users, "failed": failed_users}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when creating users"), 500


@app.route('/api/user', methods = ["PATCH"])
@accesskey_login
@dev_login
@login_required
def patch_user():
    try:
        user = request.get_json()
        user_id = dict(session).get('user', None)["id"]
        user = dbutils.update_user(user, user_id=user_id)
        return jsonify({"message": "user updated", "user": user}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when updating user"), 500

@accesskey_login
@dev_login
@login_required
@admin_required
@app.route('/api/user/<int:user_id>', methods = ["DELETE"])
def delete_user(user_id):
    try:
        user = dbutils.delete_user(user_id)
        return jsonify({"message": "user deleted successfully", "user": user}), 203
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when deleting user"), 500
# ------------------- end user -------------------

# File API endpoints
# - file [GET] -> list all files
# - file [POST]-> create a new file
# - file [PATCH] -> update file
# - file [DELETE] -> delete file

@app.route('/api/file', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_file():
    try:
        offset = int(request.args.get("offset", default=0))
        limit = int(request.args.get("limit", default=20))
        user = dict(session).get('user', None)
        files, file_count = dbutils.list_files(offset, limit, user_id=user["id"])
        return jsonify({"message": "files listed successfully", "files": files, "total_files": file_count})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when listing files"), 500

@app.route('/api/file/detail', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_file_detail():
    try:
        offset = int(request.args.get("offset", default=0))
        limit = int(request.args.get("limit", default=20))
        user = dict(session).get('user', None)
        files, file_count = dbutils.list_files_detail(offset, limit, user_id=user["id"])
        return jsonify({"message": "files listed successfully", "files": files, "total": file_count})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when listing files"), 500

@app.route('/api/file/search', methods = ["POST"])
@accesskey_login
@dev_login
@login_required
def search_file():
    try:
        data = request.get_json()
        offset = int(data.get("offset", 0))
        limit = int(data.get("limit", 20))
        fileinfo = data.get("file_info", None)
        owner_id = data.get("owner_id", None)
        collection_id = data.get("collection_id", None)
        collection_id = int(collection_id) if collection_id else None
        tt = time.time()
        files, file_count = dbutils.search_files(data.get("query", ""), session["user"]["id"], collection_id, fileinfo, owner_id, offset, limit)
        print("all:", time.time()-tt)
        return jsonify({"message": "files searched successfully", "files": files, "total": file_count})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when searching files"), 500

@app.route('/api/file/filter', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_filters():
    try:
        filter_number_category = int(request.args.get("category_filter", default=20))
        filter_number_option = int(request.args.get("option_filter", default=20))
        filters = dbutils.get_filters(session["user"]["id"], filter_number_category, filter_number_option)
        return jsonify({"message": "file filter retrieved successfully", "filters": filters})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when retrieving file filters"), 500

@app.route('/api/file', methods = ["POST"])
@accesskey_login
@dev_login
@login_required
def post_file():
    try:
        data = request.get_json()
        db_file = dbutils.create_file(db, data["filename"], data["size"], session["user"]["id"])
        return jsonify(db_file)
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when posting file"), 500

@app.route('/api/file', methods = ["PATCH"])
@accesskey_login
@dev_login
@login_required
def patch_file():
    try:
        file = request.get_json()
        dbutils.update_file(db, file)
        return jsonify(message="file updated"), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when updating file"), 500

@app.route('/api/file/log/<int:file_id>', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
@admin_required
def get_file_log(file_id):
    try:
        offset = int(request.args.get("offset", default=0))
        limit = int(request.args.get("limit", default=20))
        user = dict(session).get('user', None)
        files, log_count = dbutils.list_file_logs(offset, limit, file_id)
        return jsonify({"message": "file log listed successfully", "files": files, "total_logs": log_count})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when listing file log"), 500

@app.route('/api/user/log/<int:user_id>', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
@admin_required
def get_user_log(user_id):
    try:
        offset = int(request.args.get("offset", default=0))
        limit = int(request.args.get("limit", default=20))
        files, log_count = dbutils.list_user_logs(offset, limit, user_id=user_id)
        return jsonify({"message": "logs listed successfully", "logs": files, "total_logs": log_count})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when listing user log"), 500

@app.route('/api/file/metadata/<int:file_id>', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_file_meta(file_id):
    try:
        metadata = dbutils.get_file_metadata(db, file_id, session["user"]["id"])
        return jsonify(meta=metadata), 200
    except Exception:
        return jsonify(message="An error occurred when retrieving metadata for file"), 500

@app.route('/api/file/metadata/list/<int_list:file_ids>', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_file_meta_list(file_ids):
    try:
        metas = []
        for file_id in file_ids:
            metadata = dbutils.get_file_metadata(db, file_id, session["user"]["id"])
            metas.append({"id": file_id, "metadata": metadata})
        return jsonify(meta=metas), 200
    except Exception:
        return jsonify(message="An error occurred when retrieving metadata for files"), 500


@app.route('/api/file/<int:file_id>', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_file_by_id(file_id):
    try:
        res = dbutils.get_file_by_id(file_id, dict(session).get('user', None))
        return jsonify(res), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to retrieve file"), 500

@app.route('/api/file/<int:file_id>', methods = ["DELETE"])
@accesskey_login
@dev_login
@login_required
def delete_file(file_id):
    try:
        user = dict(session).get('user', None)
        res = dbutils.delete_file(file_id, user)
        if res == 1: 
            return jsonify({"message": "File deleted", "file": file_id}), 200
        else:
            return jsonify(message="No permission to delete file"), 403
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to delete file"), 500

@app.route('/api/file/download/<int:fileid>', methods = ['GET'])
@accesskey_login
@dev_login
@login_required
def download(fileid):
    try:
        user = dict(session).get('user', None)
        db_file = dbutils.download_file(fileid, user["id"])
        response = s3utils.sign_get_file(db_file.uuid+"/"+db_file.name, conf["aws"])
        return jsonify({"message": "URL signed", "url": response}), 200

    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to sign URL"), 500

@app.route('/api/file/download/list/<int_list:fileids>', methods = ['GET'])
@accesskey_login
@dev_login
@login_required
def download_list(fileids):
    try:
        user = dict(session).get('user', None)
        url_list = []
        for fileid in fileids:
            db_file = dbutils.download_file(fileid, user["id"])
            response = s3utils.sign_get_file(db_file.uuid+"/"+db_file.name, conf["aws"])
            url_list.append({"id": fileid, "url": response})
        return jsonify(urls=url_list), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to sign URL"), 500

@app.route('/api/file/annotate/<int:fileid>', methods = ['post'])
@accesskey_login
@dev_login
@login_required
def annotate_file(fileid):
    try:
        user = dict(session).get('user', None)
        data = request.get_json()
        if dbutils.is_owner_file(user["id"], fileid) or dbutils.is_admin(user["id"]):
            db_file = dbutils.annotate_file(fileid, data)
            return jsonify({"message": "file updated", "file": db_file}), 200
        else:
            return jsonify(message="No permission to annotate file"), 403
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when annotating file"), 500

# ============== file upload functions ===============
@app.route('/api/file/upload', methods = ['POST'])
@accesskey_login
@dev_login
@login_required
@upload_credentials
def upload():
    try:
        data = request.get_json()
        db_file = dbutils.create_file(db, data["filename"], data["size"], session["user"]["id"])
        # check whether user has rights to upload data
        # general upload rights, resource write credentials (e.g. user is allowed to write)
        response = s3utils.sign_upload_file(db_file["uuid"]+"/"+data["filename"], conf["aws"])
        #dbutils.upload_complete_file
        return jsonify({"message": "URL signed", "url": response, "file": db_file}), 200
    except Exception:
        return jsonify(message="An error occurred when attempting to sign URL"), 500

@app.route('/api/file/startmultipart', methods = ['POST'])
@accesskey_login
@dev_login
@login_required
@upload_credentials
def startmultipart():
    try:
        data = request.get_json()
        db_file = dbutils.create_file(db, data["filename"], data["size"], session["user"]["id"])
        response = s3utils.start_multipart(db_file["uuid"]+"/"+data["filename"], conf["aws"])
        res = {'status': 'ok', 'upload_id': response, 'uuid': db_file["uuid"], 'id': db_file["id"]}
        return jsonify({"message": "multipart upload started", 'upload_id': response, 'uuid': db_file["uuid"], 'id': db_file["id"]}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to start multipart upload"), 500

@app.route('/api/file/signmultipart', methods = ['POST'])
@accesskey_login
@dev_login
@login_required
@upload_credentials
def signmultipart():
    try:
        data = request.get_json()
        url = s3utils.sign_multipart(data["filename"], data["upload_id"], data["part_number"], conf["aws"])
        return jsonify({'message': 'multipart upload URL signed', 'url': url}), 200 
    except Exception:
        return jsonify(message="An error occurred when attempting to sign multipart upload URL"), 500

@app.route('/api/file/completemultipart', methods = ['POST'])
@accesskey_login
@dev_login
@login_required
@upload_credentials
def completemultipart():
    try:
        data = request.get_json()
        s3utils.complete_multipart(data["filename"], data["upload_id"], data["parts"], conf["aws"])
        return jsonify({'message': 'multipart upload completed'}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to complete multipart upload"), 500

# ------------------- end file -------------------

# Role API endpoints
# - user [GET] -> list all roles
# - user [POST]-> create a new role
# - user [PATCH] -> update role
# - user [DELETE] -> delete role
@app.route('/api/role', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
@admin_required
def get_role():
    try:
        roles = dbutils.list_roles()
        return jsonify(roles=roles), 200
    except Exception:
        return jsonify(message="An error occurred when attempting to list roles"), 500

@app.route('/api/role', methods = ["POST"])
@accesskey_login
@dev_login
@login_required
@admin_required
def post_role():
    try:
        data = request.get_json()
        role = dbutils.create_role(data)
        return jsonify({"message": "role created", "role": role}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to create role"), 500

@app.route('/api/role', methods = ["PATCH"])
@accesskey_login
@dev_login
@login_required
@admin_required
def patch_role():
    try:
        data = request.get_json()
        role = dbutils.update_role(data)
        return jsonify({"message": "role updated", "role": role}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to update role"), 500

@app.route('/api/role/<int:role_id>', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
@admin_required
def get_role_by_id(role_id):
    try:
        role = dbutils.get_role_by_id(role_id)
        print(role)
        return jsonify({"message": "role retrieved", "role": role}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to get role"), 500

@app.route('/api/role/<int:role_id>', methods = ["DELETE"])
@accesskey_login
@dev_login
@login_required
@admin_required
def delete_role(role_id):
    try:
        role = dbutils.delete_role(role_id)
        return jsonify({"message": "role deleted", "role": role}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to delete role"), 500


# ------------------- end role -------------------

# Role API endpoints
# - user [GET] -> list all roles
# - user [POST]-> create a new role
# - user [PATCH] -> update role
# - user [DELETE] -> delete role
@app.route('/api/policy', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
@admin_required
def get_policy():
    try:
        policies = dbutils.list_policies()
        return jsonify(policies=policies), 200
    except Exception:
        return jsonify(message="An error occurred when attempting to list policies"), 500

@app.route('/api/policy', methods = ["POST"])
@accesskey_login
@dev_login
@login_required
@admin_required
def post_policy():
    try:
        data = request.get_json()
        policy = dbutils.create_policy(data)
        return jsonify({"message": "policy created", "policy": policy}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to create policy"), 500

@app.route('/api/policy/<int:policy_id>', methods = ["DELETE"])
@accesskey_login
@dev_login
@login_required
@admin_required
def delete_policy(policy_id):
    try:
        policy = dbutils.delete_policy(policy_id)
        return jsonify({"message": "policy deleted", "policy": policy}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to delete policy"), 500
        


# Collection API endpoints
# - user [GET] -> list all collections
# - user [POST]-> create a new collections
# - user [PATCH] -> update collections
# - user [DELETE] -> delete collections
@app.route('/api/collection', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_collections():
    try:
        user = dict(session).get('user', None)
        collections = dbutils.list_collections(user["id"])
        return jsonify({"message": "collections listed successfully", "collections": collections})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to list collections"), 500

@app.route('/api/collection/<int:collection_id>', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_collection_by_id(collection_id):
    try:
        user = dict(session).get('user', None)
        collection = dbutils.get_collection(collection_id, user["id"])
        return jsonify(collection)
    except Exception:
        traceback.print_exc()


@app.route('/api/collection/<int_list:collection_ids>', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_collections_list(collection_ids):
    try:
        collections = []
        user = dict(session).get('user', None)
        for collection_id in collection_ids:
            collection = dbutils.get_collection(collection_id, user["id"])
            collections.append(collection)
        return jsonify(collections=collections), 200
    except Exception:
        return jsonify(message="An error occurred when retrieving collections"), 500


@app.route('/api/collection/<int:collection_id>/files', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_collection_files(collection_id):
    try:
        offset = int(request.args.get("offset", 0))
        limit = int(request.args.get("limit", 20))
        user = dict(session).get('user', None)
        collection = dbutils.get_collection_files(collection_id, offset, limit, user["id"])
        return jsonify(collection)
    except Exception:
        traceback.print_exc()

@app.route('/api/collection', methods = ["POST"])
@accesskey_login
@dev_login
@login_required
def post_collection():
    try:
        user = dict(session).get('user', None)
        data = request.get_json()
        collection = dbutils.create_collection(data, user["id"])
        return jsonify({"message": "collections created successfully", "collection": collection})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to create collection"), 500

@app.route('/api/collection', methods = ["PATCH"])
@accesskey_login
@dev_login
@login_required
def patch_collection():
    try:
        data = request.get_json()
        user = dict(session).get('user', None)
        collection = dbutils.update_collection(data, user["id"])
        return jsonify({"message": "collection updated successfully", "collection": collection})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to update collection"), 500

@app.route('/api/collection/<int:collection_id>', methods = ["DELETE"])
@accesskey_login
@dev_login
@login_required
def delete_collection(collection_id):
    try:
        user = dict(session).get('user', None)
        collection = dbutils.delete_collection(collection_id, user["id"])
        return jsonify({"message": "collection deleted successfully", "collection": collection})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when attempting to delete collection"), 500

# ------------------- end collection -------------------

# Accesskey API endpoints
# - user [GET] -> list all roles
# - user [POST]-> create a new role
# - user [DELETE] -> delete role
@app.route('/api/user/accesskey', methods = ["GET"])
@accesskey_login
@dev_login
@login_required
def get_access_keys():
    try:
        user = dict(session).get('user', None)
        access_keys = dbutils.list_user_access_keys(user["id"])
        return jsonify({"message": "keys successfully listed", "keys": access_keys}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when listing keys"), 500


@app.route('/api/user/accesskey/<int:expiration>', methods = ["POST"])
@accesskey_login
@dev_login
@login_required
def post_access_key(expiration):
    try:
        user = dict(session).get('user', None)
        key = dbutils.create_access_key(user["id"], expiration)
        return jsonify({"key": key}), 200
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when creating key"), 500

@app.route('/api/user/accesskey/<int:akey>', methods = ["DELETE"])
@accesskey_login
@dev_login
@login_required
def delete_access_key(akey):
    try:
        user = dict(session).get('user', None)
        res = dbutils.delete_access_key(user["id"], akey)
        if res == 1: 
            return jsonify({"action": "key deleted", "key": akey}), 200
        else:
            return jsonify(message="No permission to delete key"), 500
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when deleting key"), 500

@app.route('/api/user/keylogin', methods=["GET"])
@accesskey_login
@dev_login
@login_required
def keylogin():
    user = dbutils.get_key_user(user_key)
    session["user"] = {"id": user.id, "first_name": user.first_name, "last_name": user.last_name, "email": user.email, "uuid": user.uuid}
    session.permanent = True

@app.route('/api/user/search', methods=["POST"])
@accesskey_login
@dev_login
@login_required
@admin_required
def search_user():
    try:
        data = request.get_json()
        offset = int(data.get("offset", 0))
        limit = int(data.get("limit", 20))
        search = data.get("search", None)
        users, user_count = dbutils.search_user(search, offset, limit)
        return jsonify({"message": "users searched successfully", "users": users, "total": user_count})
    except Exception:
        return jsonify(message="An error occurred when searching user"), 500

@app.route('/api/collection/search', methods=["POST"])
@accesskey_login
@dev_login
@login_required
def search_collection():
    try:
        data = request.get_json()
        offset = int(data.get("offset", 0))
        limit = int(data.get("limit", 20))
        search = data.get("search", None)
        user = dict(session).get('user', None)
        collections, collection_count = dbutils.search_collection(search, offset, limit, user["id"])
        return jsonify({"message": "collections searched successfully", "collections": collections, "total": collection_count})
    except Exception:
        return jsonify(message="An error occurred when searching collections"), 500

@app.route('/api/role/search', methods=["POST"])
@accesskey_login
@dev_login
@login_required
def search_role():
    try:
        data = request.get_json()
        offset = int(data.get("offset", 0))
        limit = int(data.get("limit", 20))
        search = data.get("search", None)
        roles, role_count = dbutils.search_role(search, offset, limit)
        return jsonify({"message": "roles searched successfully", "roles": roles, "total": role_count})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when searching roles"), 500

@app.route('/api/policy/search', methods=["POST"])
@accesskey_login
@dev_login
@login_required
def search_policy():
    try:
        data = request.get_json()
        offset = int(data.get("offset", 0))
        limit = int(data.get("limit", 20))
        search = data.get("search", None)
        policies, policy_count = dbutils.search_policy(search, offset, limit)
        return jsonify({"message": "policies searched successfully", "policies": policies, "total": policy_count})
    except Exception:
        traceback.print_exc()
        return jsonify(message="An error occurred when searching policies"), 500

@app.route('/api/news', methods=["GET"])
@cache.cached(timeout=360)
def get_news():
    url = "https://api.twitter.com/2/users/"+str(conf["social"]["twitter"]["account_id"])+"/tweets?tweet.fields=created_at,public_metrics"
    headers = {
        "Authorization": "Bearer "+conf["social"]["twitter"]["bearer_token"]
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json(), 200
    else:
        return jsonify(message="An error occurred when getting news"), 500

# ------------------ Login/Logout ----------------
@app.route('/api/user/login/google')
def login():
    redirect_endpoint = request.args.get('redirect_endpoint', None)
    google = oauth.create_client('google')  # create the google oauth client
    #redirect_uri = url_for('authorize', provider="google", _external=True)
    redirect_uri = conf["redirect"]["url"]+"/api/user/authorize?provider=google"
    if redirect_endpoint != None:
        session['redirect_endpoint'] = redirect_endpoint
    return google.authorize_redirect(redirect_uri)

@app.route('/api/user/login/orcid')
def login_orcid():
    redirect_endpoint = request.args.get('redirect_endpoint', None)
    orcid = oauth.create_client('orcid')  # create the orcid oauth client
    #redirect_uri = url_for('authorize', provider="orcid", _external=True)
    redirect_uri = conf["redirect"]["url"]+"/api/user/authorize?provider=orcid"
    if redirect_endpoint != None:
        session['redirect_endpoint'] = redirect_endpoint
    return orcid.authorize_redirect(redirect_uri)

@app.route('/api/user/logout')
@accesskey_login
@login_required
def logout():
    for key in list(session.keys()):
        session.pop(key)
    return redirect('/logout')

@app.route('/api/user/authorize')
def authorize():
    print(request.url)
    provider = request.args.get('provider')
    redirect_endpoint = session.get('redirect_endpoint', None)
    if provider == "google":
        google = oauth.create_client("google")
        token = google.authorize_access_token()
        response = google.get('userinfo', token=token)
        user_info = response.json()
        print(user_info, flush=True)
    elif provider == "orcid":
        orcid = oauth.create_client("orcid")
        token = orcid.authorize_access_token()
        user_name = token["name"]
        first_name = token["name"].split(" ")[0]
        last_name = token["name"].split(" ")[-1]
        orcid_id = token["orcid"]
        user_info = {"name": user_name, "first_name": first_name, "last_name": last_name, "orcid_id": orcid_id, "email": None}
    user = dbutils.get_user(db, user_info)
    user.admin = dbutils.is_admin(user.id)
    session["user"] = {"id": user.id, "first_name": user.first_name, "last_name": user.last_name, "email": user.email, "uuid": user.uuid}
    if user.admin:
        session["user"]["admin"] = user.admin
    session.permanent = True
    # do something with the token and profile
    #return redirect('/')
    if redirect_endpoint != None:
        redirect(conf["redirect"]["url"]+'/'+redirect_endpoint)
    return redirect(conf["redirect"]["url"]+'/search')

@app.route('/api/user/i', methods = ['GET'])
@accesskey_login
@dev_login
@login_required
def mycred():
    try:
        return dbutils.get_user_by_id_json(session["user"]["id"]), 200
    except Exception:
        return jsonify(message="An error occurred when updating user"), 500

@app.route('/api/user/<int:user_id>', methods = ['GET'])
@accesskey_login
@dev_login
@login_required
@admin_required
def user_by_id(user_id):
    try:
        return dbutils.get_user_by_id_json(user_id), 200
    except Exception:
        return jsonify(message="An error occurred when getting user"), 500

# ------------------- end login -------------------

# ============== policies ============
@app.route('/api/policies', methods = ['GET'])
@accesskey_login
@dev_login
@login_required
@admin_required
def list_policies():
    policies = dbutils.list_policies()
    return jsonify(policies)

# ----------- Proxy to next.js frontend -----------

@app.route('/favicon.ico')
def nothing():
    return Response()

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def proxy(*args, **kwargs):
    resp = requests.request(
        method=request.method,
        url=request.url.replace(request.host_url, conf["frontend"]["url"]),
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    response = Response(resp.content, resp.status_code, headers)
    return response

