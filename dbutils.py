import traceback
from app import db, session, User, File, Collection, DownloadLog, Role, UserRole, Policy, RolePolicy, PolicyCollections, PolicyFiles, Accesskey
import json
import jsonschema
from jsonschema import validate
import s3utils
from datetime import datetime
from sqlalchemy.orm import joinedload
from sqlalchemy.types import Integer, Float
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import JSONB
import time
from sqlalchemy import or_, update, any_, and_
import time
from itertools import chain
from functools import lru_cache
import functools
import re

class TimedCache(object):
    def __init__(self, timeout=1):
        self.timeout = timeout
        self.cache = {}
        self.timers = {}

    def __call__(self, f):
        @functools.wraps(f)
        def wrap(*args, **kwargs):
            now = time.time()
            args_key = tuple(json.dumps(arg, sort_keys=True) if isinstance(arg, dict) else arg for arg in args)
            if args_key not in self.cache or now - self.timers[args_key] > self.timeout:
                result = f(*args, **kwargs)
                self.cache[args_key] = result
                self.timers[args_key] = now
                return result
            return self.cache[args_key]
        return wrap

@TimedCache(timeout=60)
def is_admin(user_id):
    user_roles = get_user_roles(user_id)
    for r in user_roles:
        if r["name"] == "admin":
            return True
    return False

@TimedCache(timeout=60)
def is_uploader(user_id):
    user_roles = get_user_roles(user_id)
    for r in user_roles:
        if r["name"] == "uploader":
            return True
    return False

def is_owner_file(user_id, file_id):
    file = get_file(file_id)
    if file.owner_id == user_id:
        return True
    else:
        return False

def is_owner_key(user_id, key_id):
    db_access_key = db.session.query(Accesskey).filter(Accesskey.id == key_id).first()
    if db_access_key.owner_id == user_id:
        return True
    else:
        return False

def get_stats():
    file_count = db.session.query(File.id).count()
    collection_count = db.session.query(Collection.id).filter(Collection.visibility == "visible").count()
    file_sizes = db.session.query(File.size).all()
    file_size_sum = 0
    for file_size in file_sizes:
        file_size_sum = file_size_sum+file_size[0]
    return {"files": file_count, "datasets": collection_count, "size": file_size_sum}

def get_user_by_id_json(id):
    db_user = db.session.query(User).filter(User.id == id).first()
    user = ""
    if db_user:
        role_list = []
        for role in db_user.roles:
            role_list.append({"id": role.id, "name": role.name, "description": role.description})
        user = {"id": db_user.id, "name": db_user.name, "first_name": db_user.first_name, "last_name": db_user.last_name, "email": db_user.email, "affiliation": db_user.affiliation, "creation_date": db_user.creation_date, "orcid_id": db_user.orcid_id, "uuid": db_user.uuid, "storage_quota": db_user.storage_quota, "roles": role_list}
    return user

def get_user_by_id(id):
    db_user = db.session.query(User).filter(User.id == id).first()
    user = ""
    if db_user:
        user = db_user
    return user

def get_user(db, user_info):
    user = ""
    if user_info.get("orcid_id") != None:
        db_user = db.session.query(User).filter(User.orcid_id == user_info["orcid_id"]).first()
        if db_user:
            user = db_user
        else:
            db_user = User(user_info["name"], user_info["first_name"], user_info["last_name"], user_info["email"], orcid_id=user_info["orcid_id"])
            db.session.add(db_user)
            db.session.commit()
            user = db.session.query(User).filter(User.orcid_id == user_info["orcid_id"]).first()
    else:
        db_user = db.session.query(User).filter(User.email == user_info["email"]).first()
        if db_user:
            user = db_user
        else:
            if "family_name" in user_info:
                db_user = User(user_info["name"], user_info["given_name"], user_info["family_name"], user_info["email"])
            else:
                db_user = User(user_info["name"], user_info["given_name"], "", user_info["email"])
            db.session.add(db_user)
            db.session.commit()
            user = db.session.query(User).filter(User.email == user_info["email"]).first()
    return user

def create_users_bulk(user_info):
    user_failed = []
    user_success = []
    for u in user_info:
        if db.session.query(User).filter(User.email == u["email"]).first() is None:
            try:
                roles = u.pop("roles", [])
                roles = db.session.query(Role).filter(Role.name.in_(roles)).all()
                u.pop("id", [])
                u.pop("uuid", [])
                user = User(**u)
                user.roles = roles
                db.session.add(user)
                db.session.commit()
                db.session.refresh(user)
                user_success.append(print_user(user))
            except Exception:
                traceback.print_exc()
                u["error"] = traceback.format_exc()
                user_failed.append(u)
        else:
            u["error"] = "user email already exists"
            user_failed.append(u)
    return (user_success, user_failed)

def create_user(user_info):
    if db.session.query(User).filter(User.email == user_info["email"]).first() is None:
        #collections = user_info.get("collections", None)
        #files = user_info.get("files", None)
        #roles = user_info.get("collections", None)
        #user_info.pop("collections", None)
        #user_info.pop("files", None)
        #user_info.pop("roles", None)
        user_info.pop("id", None)
        user_info.pop("uuid", None)
        user = User(**user_info)
        user.orcid_id = None
        #user.collections = db.session.query(Collection).filter(Collection.id.in_(collections)).all()
        #user.files  = db.session.query(File).filter(File.id.in_(files)).all()
        #user.roles = db.session.query(Role).filter(Role.id.in_(roles)).all()

        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
        return(print_user(user))
    else:
        raise Exception("User already exists")

def delete_user(user_id):
    dbuser = db.session.query(User).filter(User.id == user_id).first()
    r = print_user(dbuser)
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return(r)

def search_user(search, offset, limit):
    # Ensure 'search' is safely escaped and avoid repetitive formatting
    search_pattern = f"%{search}%"

    # Query the database with filters and apply offset/limit for efficiency
    query = db.session.query(User).filter(
        or_(User.first_name.ilike(search_pattern),
            User.last_name.ilike(search_pattern),
            User.affiliation.ilike(search_pattern))
    )

    total_users_count = query.count()
    res_users = query.offset(offset).limit(limit).all()

    return ([print_user_short(x) for x in res_users], total_users_count)

def search_collection(search, offset, limit, user_id):
    # Get user credentials and admin status
    list_creds, read_creds, write_creds = get_scope(user_id)
    is_user_admin = is_admin(user_id)
    
    # Construct the base query
    if is_user_admin:
        db_collections = Collection.query  # Admin can see all collections
    else:
        db_collections = Collection.query.filter(
            or_(
                Collection.id.in_(list_creds), 
                Collection.visibility != "hidden", 
                Collection.owner_id == user_id
            )
        )
    
    # Prepare the search pattern to prevent repetition and SQL injection
    search_pattern = f"%{search}%"

    # Apply filters for searching
    db_collections = db_collections.filter(
        or_(
            Collection.description.ilike(search_pattern),
            Collection.name.ilike(search_pattern),
            Collection.uuid.ilike(search_pattern)
        )
    )
    
    # Get total count of matched collections
    total_collections_count = db_collections.count()

    # Apply offset and limit for fetching the required subset
    res_collections = db_collections.offset(offset).limit(limit).all()

    return ([print_collection_short(collection) for collection in res_collections], total_collections_count)

def print_collection_short(collection):
    col = {}
    col["id"] = collection.id
    col["uuid"] = collection.uuid
    col["name"] = collection.name
    col["description"] = collection.description
    col["files"] = len(collection.files)
    col["collections"] = len(collection.collections)
    col["visibility"] = collection.visibility
    col["accessibility"] = collection.accessibility
    return col

def search_role(search, offset, limit):
    roles = db.session.query(Role)
    roles = roles.filter(Role.name.ilike("%{}%".format(search))).all()
    res_roles = roles[offset:(offset+limit)]
    return ([print_roles_short(x) for x in res_roles], len(roles))

def search_policy(search, offset, limit):
    policies = db.session.query(Policy)
    policies = policies.filter(Policy.name.ilike("%{}%".format(search))).all()
    res_policies = policies[offset:(offset+limit)]
    return ([print_policy(x) for x in res_policies], len(policies))

def print_roles_short(role):
    rol = {}
    rol["id"] = role.id
    rol["name"] = role.name
    rol["description"] = role.description
    rol["policies"] = [{"id":x.id, "name":x.name} for x in role.policies]
    rol["creation_date"] = role.creation_date
    return rol

def list_user_quota_2(user_id):
    db_user = db.session.query(User).filter(User.id == user_id).first()
    db_files = db.session.query(File).filter(File.owner_id == user_id).all()
    quota_used = 0
    for file in db_files:
        quota_used = quota_used+file.size
    quota_used = quota_used/(1024*1024)
    return((int(quota_used), int(max(0, db_user.storage_quota - quota_used)), int(db_user.storage_quota)))

def list_user_quota(user_id):
    db_user = db.session.query(User).filter(User.id == user_id).first()
    if db_user:
        total_size = db.session.query(func.sum(File.size)).filter(File.owner_id == user_id).scalar() or 0
        quota_used = total_size / (1024 * 1024)
        return (int(quota_used), int(max(0, db_user.storage_quota - quota_used)), int(db_user.storage_quota))
    return (0, 0, 0)

def is_valid_email(email):
    # Define a basic regex pattern for email validation
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    # Use the re.match() function to check if the email matches the pattern
    if re.match(pattern, email):
        return True
    else:
        return False

def update_user(user, user_id=None):
    if user_id == user["id"] or is_admin(user_id):
        dbuser = db.session.query(User).filter(User.id == user["id"]).first()
        user.pop("creation_date", None)
        user.pop("uuid", None)
        user.pop("id", None)
        overwrite = user.pop("overwrite", False)

        roles = user.pop("roles", [])
        if is_admin(user_id):
            if overwrite:
                dbuser.roles = db.session.query(Role).filter(Role.id.in_(roles)).all()
            else:
                dbuser.roles = list(set(dbuser.roles + db.session.query(Role).filter(Role.id.in_(roles)).all()))

        if "name" in user:
            dbuser.name = user["name"]
        if "first_name" in user:
            dbuser.first_name = user["first_name"]
        if "last_name" in user:
            dbuser.last_name = user["last_name"]
        if "email" in user and is_valid_email(user["email"]):
            dbuser.email = user["email"] 
        if "affiliation" in user:
            dbuser.affiliation = user["affiliation"]
        if "orcid_id" in user:
            if len(user["orcid_id"]) > 0:
                dbuser.orcid_id = user["orcid_id"]

        db.session.commit()

        return(print_user(dbuser))
    else:
        raise Exception("User not allowed to be modified")

# ----------- roles ----------------

def delete_role(role_id):
    dbrole = db.session.query(Role).filter(Role.id == role_id).first()
    r = print_role(dbrole)
    Role.query.filter_by(id=role_id).delete()
    db.session.commit()
    return(r)

def update_role(role):
    overwrite = False
    dbrole = db.session.query(Role).filter(Role.id == role["id"]).first()

    dbpolicies = db.session.query(Policy).all()
    dbp = []
    for p in dbpolicies:
        dbp.append(p.id)

    if "overwrite" in role.keys():
        overwrite = role["overwrite"]

    if "name" in role.keys():
        dbrole.name = role["name"]

    if "description" in role.keys():
        dbrole.description = role["description"]

    if overwrite:
        dbrole.policies = []
        for p in role["policies"]:
            if p in dbp:
                pp = db.session.query(Policy).filter(Policy.id == p).first()
                dbrole.policies.append(pp)
    else:
        for p in role["policies"]:
            if p in dbp and p not in dbrole.policies:
                pp = db.session.query(Policy).filter(Policy.id == p).first()
                dbrole.policies.append(pp)
    db.session.commit()
    return(print_role(dbrole))

def create_role(role_data):
    if db.session.query(Role).filter(Role.name == role_data["name"]).first() is None:
        role = Role(name=role_data["name"], description=role_data.pop("description", None), policies=[])
        policies = role_data.pop("policies", [])
        for p in policies:
            policy = db.session.query(Policy).filter(Policy.id == p).first()
            if policy is not None:
                role.policies.append(policy)
        db.session.add_all([role])
        db.session.commit()
        db.session.refresh(role)
        return(print_role(role))
    else:
        raise Exception("Role name already exists. Choose a different name")

def list_roles():
    db_roles = Role.query.all()
    roles = []
    for role in db_roles:
        r = print_role(role)
        roles.append(r)
    return roles

def get_role_by_id(role_id):
    db_roles = Role.query.filter(Role.id == role_id).first()
    return print_role(db_roles)

def print_role(role):
    policies = []
    if role.policies is not None:
        for policy in role.policies:
            pp = print_policy(policy)
            policies.append(pp)
    return({"id": role.id, "name": role.name, "description": role.description, "policies": policies})

def print_policy(policy):
    pp = dict(policy.__dict__)
    pp.pop('_sa_instance_state', None)

    files = []
    collections = []
    for collection in policy.collections:
        c = dict(collection.__dict__)
        c.pop('_sa_instance_state', None)
        collections.append({"id":c["id"], "name":c["name"]})

    files = []
    for file in policy.files:
        f = dict(file.__dict__)
        f.pop('_sa_instance_state', None)
        files.append({"id":f["id"], "display_name":f["display_name"]})
    pp["collections"] = collections
    pp["files"] = files
    return(pp)

# ===== files ========

def create_file(db, file_name, file_size, user_id):
    user = db.session.query(User).filter(User.id == user_id).first()
    total_file_size = db.session.query(func.sum(File.size)).filter(File.owner_id == user.id).scalar() or 0
    total_file_size += file_size
    total_file_size = total_file_size/(1024*1024)
    print(file_name, file_size)
    if total_file_size <= user.storage_quota:
        file = File(name=file_name, user=user, size=file_size, collection_id=1, status="uploading")
        db.session.add_all([file])
        db.session.commit()
        db.session.refresh(file)
        return {"id": file.id, "name": file.name, "display_name": file.name, "uuid": file.uuid, "status": file.status, "date": file.creation_date, "owner_id": file.owner_id, "owner_name": user.name, "size": file.size, "accessibility": file.accessibility, "visibility": file.visibility, "collection_id": file.collection_id}
    else:
        raise Exception("Storage quota exceeded.")

def get_file(file_id):
    return File.query.filter_by(id=file_id).first()

def log_file_download(user_id, file_id):
    new_log = DownloadLog(user_id=user_id, file_id=file_id)
    db.session.add(new_log)
    db.session.commit()

def download_file(file_id, user_id):
    if is_admin(user_id):
        log_file_download(user_id, file_id)
        return db.session.query(File).filter(File.id == file_id).first()
    else:
        (list_creds, read_creds, write_creds) = get_scope(user_id)
        files = db.session.query(File).filter(File.id == file_id)
        files = files.join(Collection, File.collection_id == Collection.id).filter(
                or_(
                    File.collection_id.in_(read_creds),
                    File.id.in_(read_creds),
                    File.accessibility != "locked",
                    File.owner_id == user_id,
                    Collection.accessibility == "open"
                )
        )
        down_file = files.first()

        if down_file:
            log_file_download(user_id, file_id)

        return down_file

def delete_file(file_id, user):
    if is_admin(user["id"]) or is_owner_file(user["id"], file_id):
        file = File.query.filter_by(id=file_id).first()
        s3utils.delete_file(file.uuid, file.name)
        db.session.delete(file)
        db.session.commit()
        return 1
    else:
        return 0

def list_files(offset, limit, user_id):
    st = time.time()
    (list_creds, read_creds, write_creds) = get_scope(user_id)
    
    db_query = db.session.query(File, User.name).filter(
        or_(
            File.collection_id.in_(list_creds),
            File.id.in_(list_creds),
            File.visibility != "hidden",
            File.owner_id == user_id
        )
    ).filter(
        File.owner_id == User.id
    )
    
    db_files = db_query.order_by(File.id).offset(offset).limit(limit).all()
    
    file_count = db_query.count()
    files = []
    for file in db_files:
        files.append({"id": file[0].id, "name": file[0].name, "display_name": file[0].display_name, "uuid": file[0].uuid, "status": file[0].status, "date": file[0].creation_date, "owner_id": file[0].owner_id, "owner_name": file[1], "visibility": file[0].visibility, "accessibility": file[0].accessibility, 'collection_id': file[0].collection_id, 'size': file[0].size, 'checksum': file[0].checksum})
    print("elapsed:", time.time()-st)
    return files, file_count

def list_files_detail(offset, limit, user_id=None):
    
    (list_creds, read_creds, write_creds) = get_scope(user_id)
    
    db_query = db.session.query(File, User.name).filter(
        or_(
            File.collection_id.in_(list_creds),
            File.id.in_(list_creds),
            File.visibility != "hidden",
            File.owner_id == user_id
        )
    ).filter(
        File.owner_id == User.id
    )
    
    db_files = db_query.order_by(File.id).offset(offset).limit(limit).all()
    
    file_count = db_query.count()

    files = []
    for file in db_files:
        owner = file[1]
        collection = file[2]
        owner_result = {"first_name": owner.first_name, "last_name": owner.last_name, "id": owner.id, "uuid": owner.uuid}
        collection_result = {"id": collection.id, "name": collection.name, "uuid": collection.uuid}
        file_result = {"id": file[0].id, "name": file[0].name, "display_name": file[0].display_name, "uuid": file[0].uuid, "status": file[0].status, "date": file[0].creation_date, "owner": owner_result, "visibility": file[0].visibility, "accessibility": file[0].accessibility, 'collection': collection_result, 'size': file[0].size}
        files.append(file_result)
    return files, file_count

def list_user_files(user_id, offset, limit):
    #file_count = File.query.filter_by(File.owner_id=user_id).order_by(File.id).count()
    file_count = db.session.query(File).filter(File.owner_id == user_id).count()
    #db_files = File.query.filter_by(owner_id=user_id).order_by(File.id).offset(offset).limit(limit).all()
    db_files = db.session.query(File, User, Collection).filter(File.owner_id == user_id).filter(File.owner_id == User.id).filter(File.collection_id == Collection.id).order_by(File.id).offset(offset).limit(limit).all()
    
    files = []
    for file in db_files:
        owner = file[1]
        collection = file[2]
        owner_result = {"first_name": owner.first_name, "last_name": owner.last_name, "id": owner.id, "uuid": owner.uuid}
        collection_result = {"id": collection.id, "name": collection.name, "uuid": collection.uuid}
        file_result = {"id": file[0].id, "name": file[0].name, "display_name": file[0].display_name, "uuid": file[0].uuid, "status": file[0].status, "date": file[0].creation_date, "owner": owner_result, "visibility": file[0].visibility, "accessibility": file[0].accessibility, 'collection': collection_result, 'size': file[0].size}
        files.append(file_result)
    return files, file_count

def list_user_collections(user_id, offset, limit):
    collection_count = db.session.query(Collection).filter(Collection.owner_id == user_id).count()
    db_collections = db.session.query(Collection).filter(Collection.owner_id == user_id).order_by(Collection.id).offset(offset).limit(limit).all()
    collections = []
    for collection in db_collections:
        collections.append(print_collection(collection))
    return collections, collection_count

def list_collection_files(user_id):
    return []

@TimedCache(timeout=2)
def search_files(query_data, user_id, collection_id, file_name, owner_id, offset=0, limit=20):
    
    (list_creds, read_creds, write_creds) = get_scope(user_id)

    files = db.session.query(File)
    if collection_id is not None:
        files = files.filter(File.collection_id == collection_id)
    
    if file_name is not None:
        files = files.filter(or_(File.display_name.ilike("%{}%".format(file_name)), File.description.ilike("%{}%".format(file_name))))
    
    if owner_id is not None:
        files = files.filter(File.owner_id == owner_id)
    
    if not is_admin(user_id):
        files = files.filter(
            or_(
                File.collection_id.in_(list_creds),
                File.id.in_(list_creds),
                File.visibility != "hidden",
                File.owner_id == user_id
            )
        )

    if query_data != "":
        files = filterjson(files, File.meta, query_data)

    file_total = files.count()
    files = files.offset(offset).limit(limit)

    res_files = []
    for file in files:
        if is_admin(user_id):
            permissions = ["list", "read", "write"]
        else:
            permissions = ["list"]
            if file.uuid in read_creds:
                permissions.append("read")
            if file.uuid in write_creds:
                permissions.append("write")
        f = dict(file.__dict__)
        f.pop('_sa_instance_state', None)
        res_files.append(f)

    rr = add_file_detail(res_files)
    return rr, file_total

def add_file_detail2(files):
    for file in files:
        file_details = db.session.query(File, User, Collection).filter(File.id == file["id"]).filter(File.owner_id == User.id).filter(File.collection_id == Collection.id).first()
        owner = {"id": file_details[1].id, "first_name": file_details[1].first_name, "last_name": file_details[1].last_name}
        collection = {"id": file_details[2].id, "name": file_details[2].name}
        
        file["owner"] = owner
        file["collection"] = collection
    return files

def add_file_detail(files):
    file_ids = [file['id'] for file in files]
    
    # Getting all file details including related user and collection info in a single query
    file_details = db.session.query(File, User, Collection)\
                             .filter(File.id.in_(file_ids))\
                             .join(User, File.owner_id == User.id)\
                             .join(Collection, File.collection_id == Collection.id)\
                             .all()

    file_details_dict = {f.id: {"owner": {"id": u.id, "first_name": u.first_name, "last_name": u.last_name},
                                "collection": {"id": c.id, "name": c.name}} 
                        for f, u, c in file_details}

    for file in files:
        file_detail = file_details_dict.get(file["id"])
        if file_detail:
            file["owner"] = file_detail["owner"]
            file["collection"] = file_detail["collection"] 

    return files

def list_users():
    db_users = User.query.order_by(User.id).all()
    users = []
    for user in db_users:
        users.append(print_user_for_list(user))
    return users

def get_user_roles(userid):
    roles = []
    for u, ur, r in db.session.query(User, UserRole, Role).filter(User.id == UserRole.user_id).filter(Role.id == UserRole.role_id).filter(User.id == userid).all():
        roles.append({"id": r.id, "name": r.name})
    #print(roles)
    return roles

def print_user(user):
    roles = []
    for r in user.roles:
        roles.append({"id": r.id, "name": r.name, "description": r.description})
    files = []
    for f in user.files:
        files.append(f.id)
    collections = []
    for c in user.collections:
        collections.append(c.id)
    user = dict(user.__dict__)
    user.pop('_sa_instance_state', None)
    user["files"] = files
    user["roles"] = roles
    user["collections"] = collections
    return(user)

def print_user_for_list(user):
    roles = []
    for r in user.roles:
        roles.append({"id": r.id, "name": r.name, "description": r.description})
    user = dict(user.__dict__)
    user.pop('_sa_instance_state', None)
    user["roles"] = roles
    return(user)

def print_user_short(user):
    ushort = {}
    ushort["id"] = user.id
    ushort["uuid"] = user.uuid
    ushort["first_name"] = user.first_name
    ushort["last_name"] = user.last_name
    ushort["name"] = user.name
    ushort["email"] = user.email
    ushort["affiliation"] = user.affiliation
    ushort["creation_date"] = user.creation_date
    ushort["roles"] = [{"id":x.id, "name":x.name} for x in user.roles]
    return ushort

def print_file():
    return({})

def print_collection(collection, scope=None, admin=False, user_id=-1):
    if admin:
        return {
            **{k: v for k, v in collection.__dict__.items() if k != '_sa_instance_state'},
            "collections": [c.id for c in collection.collections],
            "files": [f.id for f in collection.files]
        }
    elif scope:
        return {
            **{k: v for k, v in collection.__dict__.items() if k != '_sa_instance_state'},
            "collections": [c.id for c in collection.collections if (not c.visibility == "hidden" or c.id in scope or c.owner_id == user_id) or admin],
            "files": [f.id for f in collection.files if (not f.visibility == "hidden" or f.id in scope or f.owner_id == user_id) or admin]
        }
    else:
        return {
            **{k: v for k, v in collection.__dict__.items() if k != '_sa_instance_state'},
            "collections": [c.id for c in collection.collections],
            "files": [f.id for f in collection.files]
        }

def get_scope_empty(userid):
    read_cred = []
    write_cred = []
    list_cred = []
    return (set(list_cred), set(read_cred), set(write_cred))
    

def get_scope2(userid):
    read_cred, write_cred, list_cred = set(), set(), set()

    roles = db.session.query(Role).join(UserRole).filter(UserRole.user_id == userid).all()

    for r in roles:
        for p in r.policies:
            if p.effect == "allow":
                for c in p.collections:
                    add_collection_scope(c, p.action, list_cred, read_cred, write_cred)

    return (list_cred, read_cred, write_cred)

@TimedCache(timeout=30)
def get_scope(userid):
    read_cred, write_cred, list_cred = set(), set(), set()

    roles = db.session.query(Role) \
                      .options(joinedload(Role.policies).
                               joinedload(Policy.collections).
                               joinedload(Collection.collections)) \
                      .join(UserRole).filter(UserRole.user_id == userid).all()

    for r in roles:
        for p in r.policies:
            if p.effect == "allow":
                for c in p.collections:
                    add_collection_scope(c, p.action, list_cred, read_cred, write_cred)

    return list_cred, read_cred, write_cred

def add_collection_scope(collection, action, list_cred, read_cred, write_cred):
    for c in collection.collections:
        not_in = not (c.id in list_cred or c.id in read_cred or c.id in write_cred)
        if action == "list":
            list_cred.add(c.id)
        elif action == "write":
            write_cred.add(c.id)
        elif action == "read":
            read_cred.add(c.id)
        if not_in:
            add_collection_scope(c, action, list_cred, read_cred, write_cred)



def append_role(user_id, role_name):
    user = db.session.query(User).filter(User.id == user_id).first()
    role = Role.query.filter(Role.name==role_name).first()
    user.roles.append(role)
    db.session.commit()

@TimedCache(timeout=30)
def list_collections(user_id):
    st = time.time()
    list_creds, read_creds, write_creds = get_scope(user_id)
    is_user_admin = is_admin(user_id)
    if is_user_admin:
        db_collections = Collection.query.all()
    else:
        db_collections = Collection.query.filter(
            or_(
                Collection.id.in_(list_creds), 
                Collection.visibility != "hidden", 
                Collection.owner_id == user_id
            )).all()
    
    print("collection time", time.time()-st)
    return [print_collection(collection, list_creds, is_user_admin, user_id) for collection in db_collections]

def create_collection(collection, user_id):
    collection.pop("collections", None)
    collection.pop("files", None)
    collection.pop("id", None)
    collection.pop("uuid", None)
    collection["owner_id"] = user_id
    if "parent_collection_id" in collection:
        if not db.session.query(Collection).filter(Collection.id == collection["parent_collection_id"]).first():
            raise Exception("Invalid parent, collection does not exist")
    else:
        collection["parent_collection_id"] = 1
    dbcollection = Collection(**collection)
    db.session.add_all([dbcollection])
    db.session.commit()
    db.session.refresh(dbcollection)
    return(print_collection(dbcollection))

def update_collection(collection, user_id):
    dbcollection = db.session.query(Collection).filter(Collection.id == collection["id"]).first()
    if dbcollection.owner_id == user_id or is_admin(user_id):
        #dbroot = db.session.query(Collection).filter(Collection.id == 1).first()
        collection.pop("creation_date", None)
        collection.pop("uuid", None)
        collection.pop("id", None)
        collections = collection.pop("collections", [])
        parent_path = get_parent_collection_path(dbcollection.id)
        for cid in collections:
            if cid in [x["id"] for x in parent_path]:
                raise Exception("Invalid child, child collection is also parent (circular collection path).")
        files = collection.pop("files", [])
        overwrite = collection.pop("overwrite", False)

        if overwrite:
            for c in dbcollection.collections:
                if c.id not in collections:
                    c.parent_collection_id = 1
            for f in dbcollection.files:
                if f.id not in files:
                    f.collection_id = 1
            db.session.commit()
            db.session.refresh(dbcollection)
            dbcollection.collections = db.session.query(Collection).filter(Collection.id.in_(collections)).all()
            dbcollection.files = db.session.query(File).filter(File.id.in_(files)).all()
        else:
            dbcollection.collections = list(set(dbcollection.collections + db.session.query(Collection).filter(Collection.id.in_(collections)).all()))
            dbcollection.files  = list(set(dbcollection.files + db.session.query(File).filter(File.id.in_(files)).all()))

        if "name" in collection:
            dbcollection.name = collection["name"]
        if "description" in collection:
            dbcollection.description = collection["description"]
        if "image_url" in collection:
            dbcollection.image_url = collection["image_url"]
        if "visibility" in collection:
            dbcollection.visibility = collection["visibility"]
        if "affiliation" in collection:
            dbcollection.affiliation = collection["affiliation"]
        if "owner_id" in collection:
            dbcollection.owner_id = collection["owner_id"]
        if "parent_collection_id" in collection:
            if collection["parent_collection_id"] != dbcollection.id:
                dbcollection.parent_collection_id = collection["parent_collection_id"]
        if "visibility" in collection:
            dbcollection.visibility = collection["visibility"]
        if "accessibility" in collection:
            dbcollection.accessibility = collection["accessibility"]
        
        db.session.commit()
        db.session.refresh(dbcollection)
        return(print_collection(dbcollection))
    else:
        raise Exception("not owner or admin of collection")

def delete_collection(collection_id, user_id):
    if collection_id != 1:
        db_collection = db.session.query(Collection).filter(Collection.id == collection_id).first()
        if db_collection.owner_id == user_id or is_admin(user_id):
            query = update(File).where(File.collection_id == collection_id).values(collection_id=1)
            db.session.execute(query)
            db.session.commit()
            query = update(Collection).where(Collection.parent_collection_id == collection_id).values(parent_collection_id=1)
            db.session.execute(query)
            db.session.commit()
            db_collection = db.session.query(Collection).filter(Collection.id == collection_id).first()
            c = print_collection(db_collection)
            db.session.query(Collection).filter(Collection.id == collection_id).delete()
            db.session.commit()
            return(c)
        else:
            raise Exception("needs to be oner of admin to delete collection")
    else:
        raise Exception("root collection cannot be deleted")

def get_collection(collection_id, user_id):
    list_creds, read_creds, write_creds = get_scope(user_id)
    is_user_admin = is_admin(user_id)

    query_result = db.session.query(Collection, User).filter(
        Collection.id == collection_id,
        User.id == Collection.owner_id
    ).first()

    if not query_result:
        return None

    collection, db_owner = query_result

    owner = {
        "id": db_owner.id,
        "name": db_owner.name,
        "firstname": db_owner.first_name,
        "lastname": db_owner.last_name,
        "affiliation": db_owner.affiliation
    }

    sub_collections = Collection.query.filter(
        Collection.parent_collection_id == collection_id
    ).order_by(Collection.id)
    
    sub_files = File.query.filter(
        File.collection_id == collection_id
    ).order_by(File.id)

    child_collections = [
        {"id": sc.id, "name": sc.name, "uuid": sc.uuid}
        for sc in sub_collections
        if sc.uuid in list_creds or sc.visibility == "visible" or is_user_admin
    ]

    return {
        "id": collection.id,
        "name": collection.name,
        "description": collection.description,
        "uuid": collection.uuid,
        "parent_collection_id": collection.parent_collection_id,
        "date": collection.creation_date,
        "owner_id": collection.owner_id,
        "owner": owner,
        "image_url": collection.image_url,
        "collections": sub_collections.count(),
        "child_collections": child_collections,
        "files": sub_files.count(),
        "accessibility": collection.accessibility,
        "visibility": collection.visibility,
        "path": get_parent_collection_path(collection_id),
    }

def get_collection_old(collection_id, user_id):
    (list_creds, read_creds, write_creds) = get_scope(user_id)
    #collection = Collection.query.filter(Collection.id==collection_id).first()
    query_result = db.session.query(Collection, User).filter(Collection.id==collection_id).filter(User.id == Collection.owner_id).first()
    collection = query_result[0]
    db_owner = query_result[1]
    owner = {"id": db_owner.id, "name": db_owner.name, "firstname": db_owner.first_name, "lastname": db_owner.last_name, "affiliation": db_owner.affiliation}
    sub_collections = Collection.query.filter(Collection.parent_collection_id==collection_id).order_by(Collection.id).all()
    sub_files = File.query.filter(File.collection_id==collection_id).order_by(File.id).all()
    collection_return = {"id": collection.id, "name": collection.name, "description": collection.description, "uuid": collection.uuid, "parent_collection_id": collection.parent_collection_id, "date": collection.creation_date, "owner_id": collection.owner_id, "owner": owner, "image_url": collection.image_url, "collections": len(sub_collections), "child_collections": [], "files": len(sub_files), "accessibility": collection.accessibility, "visibility": collection.visibility}
    # collection_return = {"id": collection.id, "name": collection.name, "description": collection.description, "uuid": collection.uuid, "parent_collection_id": collection.parent_collection_id, "date": collection.creation_date, "owner_id": collection.owner_id, "child_collections": [], "child_files": []}
    
    for sc in sub_collections:
        if sc.uuid in list_creds or sc.visibility == "visible" or is_admin(user_id):
            temp_collection = {"id": sc.id, "name": sc.name, "uuid": sc.uuid}
            collection_return["child_collections"].append(temp_collection)
    
    # for file in sub_files:
    #     if file.uuid in list_creds or file.visibility == "visible":
    #         permissions = ["list"]
    #         if file.uuid in read_creds:
    #             permissions.append("read")
    #         if file.uuid in write_creds:
    #             permissions.append("write")
    #         temp_file = {"id": file.id, "name": file.name, "display_name": file.display_name, "uuid": file.uuid, "status": file.status, "date": file.creation_date, "owner_id": file.owner_id, "visibility": file.visibility, "accessibility": file.accessibility, 'collection_id': file.collection_id, 'size': file.size, "permissions": permissions}
    #         collection_return["child_files"].append(temp_file)
    
    collection_return["path"] = get_parent_collection_path(collection_id)
    return collection_return

@TimedCache(timeout=10)
def get_collection_files(collection_id, offset, limit, user_id):
    
    st = time.time()
    list_creds, read_creds, write_creds = get_scope(user_id)
    print("get scope", time.time()-st, list_creds)

    st = time.time()
    collection = Collection.query.get(collection_id)
    print("get collection", time.time()-st)

    is_user_admin = is_admin(user_id)
    if collection is None or (collection.uuid not in list_creds and not is_user_admin):
        return []

    st = time.time()
    if is_user_admin:
        files_query = File.query.filter(
            File.collection_id == collection_id,
        ).offset(offset).limit(limit)
    else:
        files_query = File.query.filter(
            File.collection_id == collection_id,
            or_(File.collection_id.in_(list_creds), File.visibility == "visible"),
        ).offset(offset).limit(limit)
    print("get files", time.time()-st)

    st = time.time()
    total_files = files_query.count()
    print("get count", time.time()-st)
    
    
    st = time.time()
    files = []
    for file in files_query:
        permissions = ["list"]

        temp_file = {"id": file.id, "name": file.name, "display_name": file.display_name, "uuid": file.uuid, 
                    "status": file.status, "date": file.creation_date, "owner_id": file.owner_id, 
                    "visibility": file.visibility, "accessibility": file.accessibility, 
                    'collection_id': file.collection_id, 'size': file.size, "permissions": permissions}
                    
        files.append(temp_file)

    print("format files", time.time()-st)
    print("--------------------")

    return {"files": files, "total_files": total_files}

def get_collection_files_old(collection_id, offset, limit, user_id):
    import time
    st = time.time()
    (list_creds, read_creds, write_creds) = get_scope(user_id)
    collection = Collection.query.filter(Collection.id==collection_id).first()
    print(time.time()-st)
    if collection.uuid in list_creds or is_admin(user_id):
        files = []
        sub_files = File.query.filter(File.collection_id==collection_id).order_by(File.id).all()
        for file in sub_files:
            if file.uuid in list_creds or file.visibility == "visible" or is_admin(user_id):
                permissions = ["list"]
                if file.uuid in read_creds:
                    permissions.append("read")
                if file.uuid in write_creds:
                    permissions.append("write")
                temp_file = {"id": file.id, "name": file.name, "display_name": file.display_name, "uuid": file.uuid, "status": file.status, "date": file.creation_date, "owner_id": file.owner_id, "visibility": file.visibility, "accessibility": file.accessibility, 'collection_id': file.collection_id, 'size': file.size, "permissions": permissions}
                files.append(temp_file)
        offset = max(offset, 0)
        limit = min(limit, len(files))
        return {"files": files[offset:(offset+limit)], "total_files": len(files)}
    else:
        return []

def get_parent_collection_path(collection_id):
    collection_path = []
    collection = Collection.query.filter(Collection.id==collection_id).first()
    collection_path.insert(0,{"id": collection.id, "name": collection.name, "description": collection.description, "uuid": collection.uuid})
    while collection.parent_collection_id and collection.parent_collection_id != collection.id:
        if len(collection_path) < 30:
            collection = Collection.query.filter(Collection.id==collection.parent_collection_id).first()
            collection_path.insert(0,{"id": collection.id, "name": collection.name, "description": collection.description, "uuid": collection.uuid})
        else:
            break
    return collection_path

def update_file(db, file):
    db_file = db.session.query(File).filter(File.id == file["id"]).first()
    
    if "display_name" in file:
        db_file.display_name = file["display_name"]
    if "owner_id" in file:
        db_file.owner_id = file["owner_id"]
    if "collection_id" in file:
        db_file.collection_id = file["collection_id"]
    if "visibility" in file:
        db_file.visibility = file["visibility"]
    if "status" in file:
        db_file.status = file["status"]
    if "accessibility" in file:
        db_file.accessibility = file["accessibility"]
    if "meta" in file:
        db_file.meta = file["meta"]

    db.session.commit()

def file_checksum_status():
    db_files = db.session.query(File).filter(File.checksum == "").all()
    for db_file in db_files:
        try:
            checksum = s3utils.get_file_checksum(f"{db_file.uuid}/{db_file.name}")
            db_file.status = "ready"
            db_file.checksum = checksum
        except Exception:
            print("checksum missing for", db_file.name)
    
    db.session.commit()

def list_policies():
    db_policies = db.session.query(Policy).order_by(Policy.id).all()
    policies = []
    for policy in db_policies:
        policies.append(print_policy(policy))
    return policies

def create_policy(data):
    collections = []
    if "collections" in data:
        for collection in data["collections"]:
            db_collection = db.session.query(Collection).filter(Collection.id==collection).first()
            if db_collection is not None:
                collections.append(db_collection)
    files = []
    
    if "files" in data:
        for file in data["files"]:
            db_file = db.session.query(File).filter(File.id==file).first()
            if db_file is not None:
                files.append(db_file)

    policy = Policy(action=data["action"], effect=data["effect"], collections=collections, files=files, name=data.pop("name", None), description=data.pop("description", None))
    db.session.add_all([policy])
    db.session.commit()
    db.session.refresh(policy)
    return(print_policy(policy))

def delete_policy(policy_id):
    dbpolicy = db.session.query(Policy).filter(Policy.id == policy_id).first()
    p = print_policy(dbpolicy)
    Policy.query.filter_by(id=policy_id).delete()
    db.session.commit()
    return(p)

def list_user_access_keys(user_id):
    db_access_keys = db.session.query(Accesskey).filter(Accesskey.owner_id == user_id).order_by(Accesskey.id).all()
    access_keys = []
    for key in db_access_keys:
        access_keys.append({"id": key.id, "expiration_time": key.expiration_time, "creation_date": key.creation_date, "uuid": key.uuid});

    return access_keys

def create_access_key(user_id, expiration_time):
    user = db.session.query(User).filter(User.id == user_id).first()
    akey = Accesskey(user=user, expiration_time=expiration_time)
    db.session.add(akey)
    db.session.commit()
    db.session.refresh(akey)
    k = dict(akey.__dict__)
    k.pop('_sa_instance_state', None)
    return  k

def delete_access_key(user_id, key_id):
    if is_admin(user_id) or is_owner_key(user_id, key_id):
        db_access_key = db.session.query(Accesskey).filter(Accesskey.id == key_id).first()
        db.session.delete(db_access_key)
        db.session.commit()
        return 1
    else:
        return 0

def get_key_user(user_key):
    akey = db.session.query(Accesskey).filter(Accesskey.uuid == user_key).first()
    user = db.session.query(User).filter(User.id == akey.owner_id).first()
    return user

def key_valid(user_key):
    try:
        akey = db.session.query(Accesskey).filter(Accesskey.uuid == user_key).first()
        now = datetime.now()
        key_age = (now-akey.creation_date).seconds/60
        if key_age < akey.expiration_time:
            return True
        else:
            return False
    except Exception:
        return False

def todict(obj, classkey=None):
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            data[k] = todict(v, classkey)
        return data
    elif hasattr(obj, "_ast"):
        return todict(obj._ast())
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        return [todict(v, classkey) for v in obj]
    elif hasattr(obj, "__dict__"):
        data = dict([(key, todict(value, classkey)) 
            for key, value in obj.__dict__.items() 
            if not callable(value) and not key.startswith('_')])
        if classkey is not None and hasattr(obj, "__class__"):
            data[classkey] = obj.__class__.__name__
        return data
    else:
        return obj

def validate_json(json_data, schema_data):
    try:
        validate(instance=json_data, schema=schema_data)
    except jsonschema.exceptions.ValidationError as err:
        traceback.print_exc()
        return False
    return True

def filterjson(files, file_meta, query):
    query_keys = query.keys()
    for k in query_keys:
        if type(query[k]) == int:
            files = files.filter(file_meta[k].cast(Integer) == query[k])
        elif type(query[k]) == float:
            files = files.filter(file_meta[k].cast(Float) == query[k])
        elif query[k] == None:
            files = files.filter(file_meta.has_key(k))
        elif "%" in query[k]:
            files = files.filter(file_meta[k].astext.ilike(query[k]))
        elif type(query[k]) == str:
            files = files.filter(file_meta[k].astext == query[k])
        elif "between" in query[k].keys():
            files = files.filter(file_meta[k].cast(Float) >= query[k]["between"][0]).filter(file_meta[k].cast(Float) <= query[k]["between"][1])
        else:
            try:
                files = filterjson(files, file_meta[k], query[k])
            except Exception:
                traceback.print_exc()
    return files

def filterjson_testing(files, file_meta, query):
    query_keys = query.keys()
    for k in query_keys:
        if isinstance(query[k], dict):
            if "between" in query[k]:
                files = files.filter(file_meta[k].cast(Float) >= query[k]["between"][0])\
                             .filter(file_meta[k].cast(Float) <= query[k]["between"][1])
            else:
                files = filterjson(files, file_meta[k], query[k])
        elif isinstance(query[k], int):
            files = files.filter(file_meta[k].cast(Integer) == query[k])
        elif isinstance(query[k], float):
            files = files.filter(file_meta[k].cast(Float) == query[k])
        elif query[k] is None:
            files = files.filter(file_meta.has_key(k))
        elif isinstance(query[k], str):
            if "%" in query[k]:
                files = files.filter(file_meta[k].astext.ilike(query[k]))
            else:
                files = files.filter(file_meta[k].astext == query[k])
        else:
            raise ValueError(f"Unsupported query type for key {k}: {type(query[k])}")
    return files

def annotate_file(file_id, metadata):
    file = File.query.filter(File.id == file_id).first()
    file.meta = metadata
    db.session.commit()
    db.session.refresh(file)
    file = dict(file.__dict__)
    file.pop('_sa_instance_state', None)
    return(file)



def meta_stat2(meta, path, stat):
    for k in meta.keys():
        if str(type(meta[k])) == "<class 'sqlalchemy_json.track.TrackedList'>":
            x=1
        elif str(type(meta[k])) == "<class 'sqlalchemy_json.track.TrackedDict'>":
            stat = meta_stat(meta[k], path+"/"+k, stat)
        else:
            p = path+"/"+k
            metak = meta[k]
            if type(metak) == float:
                metak = str(int(metak))
            if p in stat.keys():
                if str(metak) in stat[p].keys():
                    stat[p][str(metak)] = stat[p][str(metak)]+1
                else:
                    stat[p][str(metak)] = 1
            else:
                temp = {str(metak): 1}
                stat[p] = temp
    return stat

@TimedCache(timeout=60)
def get_filters2(user_id, filter_number_category=20, filter_number_option=10):
    files = File.query.all()
    return collect_meta_stats(files, filter_number_category=filter_number_category, filter_number_option=filter_number_option)

def collect_meta_stats2(files, filter_number_category=20, filter_number_option=10):
    stat = {}
    filter_result = []
    for f in files:
        if f.meta != None:
            stat = meta_stat(f.meta, "", stat)
    if filter == 0:
        for s in stat.keys():
            filter_result.append({"category": s, "detail": stat[s]})
    else:
        for s in stat.keys():
            file_count = 0
            temp_stat = {}
            for key in stat[s].keys():
                if stat[s][key] >= filter_number_option:
                    file_count = file_count+stat[s][key]
                    temp_stat[key] = stat[s][key]
            if file_count >= filter_number_category:
                filter_result.append({"category": s, "detail": temp_stat})
    return filter_result

def meta_stat(meta, path, stat):
    for k, v in meta.items():
        value_type = type(v).__name__
        if value_type == "TrackedList":
            continue
        elif value_type == "TrackedDict":
            stat = meta_stat(v, path + "/" + k, stat)
        else:
            p = path + "/" + k
            v = str(int(v)) if isinstance(v, float) else v
            stat.setdefault(p, {}).setdefault(str(v), 0)
            stat[p][str(v)] += 1
    return stat

@TimedCache(timeout=30)
def get_filters(user_id, filter_number_category=20, filter_number_option=10):
    (list_creds, read_creds, write_creds) = get_scope(user_id)
    files = db.session.query(File)
    
    if not is_admin(user_id):
        files = files.filter(
            or_(
                File.collection_id.in_(list_creds),
                File.id.in_(list_creds),
                File.visibility != "hidden",
                File.owner_id == user_id
            )
        )
    return collect_meta_stats(files, filter_number_category, filter_number_option)

def collect_meta_stats(files, filter_number_category=20, filter_number_option=10):
    stat = {}
    for f in files:
        if f.meta:
            stat = meta_stat(f.meta, "", stat)

    return [{"category": s, "detail": temp_stat} for s, temp_stat in (should_filter(s, stat, filter_number_option, filter_number_category) for s in stat)] if filter_number_option > 0 else stat

def should_filter(s, stat, filter_number_option, filter_number_category):
    file_count = 0
    temp_stat = {}
    for k, v in stat[s].items():
        if v >= filter_number_option:
            file_count += v
            temp_stat[k] = v
    return (s, temp_stat) if file_count >= filter_number_category else (s, {})


def get_file_metadata(db, file_id, user_id):
    file = db.session.query(File).filter(File.id == file_id).first()
    return file.meta

def get_file_by_id(file_id, user_id):
    file = db.session.query(File, User, Collection).filter(File.id == file_id).filter(User.id == File.owner_id).filter(Collection.id == File.collection_id).first()
    owner = file[1]
    collection = file[2]
    owner_result = {"first_name": owner.first_name, "last_name": owner.last_name, "id": owner.id, "uuid": owner.uuid}
    collection_result = {"id": collection.id, "name": collection.name, "uuid": collection.uuid}
    file_result = {"id": file[0].id, "name": file[0].name, "display_name": file[0].display_name, "uuid": file[0].uuid, "status": file[0].status, "date": file[0].creation_date, "owner": owner_result, "visibility": file[0].visibility, "accessibility": file[0].accessibility, 'collection': collection_result, 'size': file[0].size, 'meta': file[0].meta, 'checksum': file[0].checksum}
    return file_result


def list_file_logs(offset, limit, file_id):
    """
    List logs for a specific file.

    :param offset: The starting point for the query.
    :param limit: The maximum number of logs to return.
    :param file_id: The ID of the file to retrieve logs for.
    :return: A tuple containing the list of logs and the total count of logs for the file.
    """
    query = db.session.query(DownloadLog).filter(DownloadLog.file_id == file_id)
    total_logs = query.count()
    
    logs = query.order_by(DownloadLog.download_timestamp.desc()).offset(offset).limit(limit).all()
    log_entries = []
    
    for log in logs:
        log_entries.append({
            "id": log.id,
            "user_id": log.user_id,
            "file_id": log.file_id,
            "download_timestamp": log.download_timestamp
        })
    
    return log_entries, total_logs

def list_user_logs(offset, limit, user_id):
    """
    List logs for a specific user.

    :param offset: The starting point for the query.
    :param limit: The maximum number of logs to return.
    :param user_id: The ID of the user to retrieve logs for.
    :return: A tuple containing the list of logs and the total count of logs for the user.
    """
    query = db.session.query(DownloadLog).filter(DownloadLog.user_id == user_id)
    total_logs = query.count()
    
    logs = query.order_by(DownloadLog.download_timestamp.desc()).offset(offset).limit(limit).all()
    log_entries = []
    
    for log in logs:
        log_entries.append({
            "id": log.id,
            "user_id": log.user_id,
            "file_id": log.file_id,
            "download_timestamp": log.download_timestamp
        })
    
    return log_entries, total_logs