from app import db, User, Collection, Role
import sys

email= sys.argv[1]
first_name = sys.argv[2]
last_name = sys.argv[3]

db.drop_all()
db.create_all()

user_1 = User(name=first_name+last_name, 
                first_name=first_name, 
                last_name=last_name,
                email=email)

root_collection = Collection(name="root", user=user_1)

admin_role = Role(name="admin")
user_1.roles.append(admin_role)

uploader_role = Role(name="uploader")
user_1.roles.append(uploader_role)

db.session.add(user_1)
db.session.commit()
