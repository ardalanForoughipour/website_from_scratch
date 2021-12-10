import hashlib


# user model functions
def save_user_to_database(connection, username, password, firstname=None):
    cursor = connection.cursor()
    m = hashlib.sha256()
    passbin = bytearray(password, 'utf-8')
    m.update(passbin)
    passHash = str(m.hexdigest())
    if firstname:
        result = cursor.execute('INSERT INTO users (username,password,firstname) VALUES (%s,%s,%s)',(username,passHash,firstname))
    else:
        result = cursor.execute('INSERT INTO users (username,password) VALUES (%s,%s) ',(username,passHash))
    connection.commit()
    cursor.close()
    return result


def update_user_in_database(connection, id, username, name, password) :
    v1 = str(username)
    v2 = str(name)
    v4 = str(id)
    m = hashlib.sha256()
    passbin = bytearray(password, 'utf-8')
    m.update(passbin)
    v3 = str(m.hexdigest())
    cursor = connection.cursor()
    update_stmnt = "UPDATE users SET username=%s, firstname= %s, password=%s WHERE id =%s;"
    result = cursor.execute(update_stmnt, (v1, v2, v3,v4))
    connection.commit()
    return result


def get_user_from_database(connection,id):
    result = []
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM users where id=%s',str(id))
    for row in cursor:
        result.append(row)
    cursor.close()
    return result


def search_user_by_username(connection, username):
    result = []
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users where username=%s", str(username))
    for row in cursor:
        result.append(row)
    cursor.close()
    return result


def get_all_users(connection):
    result = []
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM users ')
    for row in cursor:
        result.append(row)
    cursor.close()
    return result


def check_username_password(connection, username,password):
    result = []
    cursor = connection.cursor()
    m = hashlib.sha256()
    passbin = bytearray(password,'utf-8')
    m.update(passbin)
    passHash = m.hexdigest()
    cursor.execute('SELECT * FROM users where username=%s and password = %s',(str(username),str(passHash)))
    for row in cursor:
        result.append(row)
    cursor.close()
    return result


def delete_user_from_database(connection, id):
    cursor = connection.cursor()
    result = cursor.execute('DELETE FROM users WHERE id=%s',str(id))
    connection.commit()
    return result


#   news model functions
def get_a_news_from_database(connection, id):
    result = []
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM news WHERE news_id=%s',str(id))
    for r in cursor:
        result.append(r)
    return result


def get_all_news(connection):
    result = []
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM news')
    for r in cursor:
        result.append(r)
    return result


def add_news_to_database(connection, user_id, title, article):
    v1 = str(user_id)
    v2 = str(title)
    v3 = str(article)
    cursor = connection.cursor()
    add_statmt = """INSERT INTO news (user_id,title,article) values (%s,%s,%s)"""
    result = cursor.execute(add_statmt, (v1,v2,v3,))
    connection.commit()
    return result


def update_news_to_database(connection, news_id, title, article):
    v1 = str(title)
    v2 = str(article)
    v3 = str(news_id)
    cursor = connection.cursor()
    update_stmnt = "UPDATE news SET title=%s, article= %s WHERE news_id =%s;"
    result = cursor.execute(update_stmnt, (v1, v2, v3))
    connection.commit()
    return result


def delete_news_from_database(connection, news_id):
    cursor = connection.cursor()
    result = cursor.execute('DELETE FROM news WHERE news_id=%s',str(news_id))
    connection.commit()
    return result


def check_title_exists(connection, title):
    result = []
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM news WHERE title=%s', str(title))
    for r in cursor:
        result.append(r)
    return result