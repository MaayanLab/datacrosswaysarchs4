import json
import os
import psycopg2


def read_config():
    f = open('secrets/config.json')
    return json.load(f)

conf = read_config()

conn = psycopg2.connect(
        host=conf["database"]["server"],
        database=conf["database"]["name"],
        user=conf["database"]["user"],
        password=conf["database"]["pass"])

cursor = conn.cursor()

def print_table(table_name):
    sql = "SELECT * FROM "+table_name
    cursor.execute(sql)
    conn.commit()
    results = cursor.fetchall()
    widths = []
    columns = []
    tavnit = '|'
    separator = '+' 
    counter = 0
    for cd in cursor.description:
        maxv = len(cd[0])
        for res in results:
            maxv = max(maxv, len(str(res[counter])))
        widths.append(maxv)
        counter = counter+1
        columns.append(cd[0])
    for w in widths:
        tavnit += " %-"+"%ss |" % (w,)
        separator += '-'*w + '--+'
    print(separator)
    print(tavnit % tuple(columns))
    print(separator)
    for row in results:
        print(tavnit % row)
    print(separator)

print_table("users")
print_table("files")
print_table("collections")

print_table("roles")
print_table("user_roles")
print_table("policies")
