import cgi
from urllib import parse as urllib_parse
from http import HTTPStatus
from http import cookies
import hashlib
from main import authenticated_users
import utility_functions
import models
import main


# get request method
def handle_accounts_get_request(myHttpHandler, partial_path):
    if partial_path.startswith('/login/') or partial_path.endswith('/login'):
        partial_path = partial_path.replace('/login', '')
        handle_login_get_request(myHttpHandler, partial_path)
    elif partial_path.startswith('/logout/'):
        partial_path = partial_path.replace('/logout', '')
        handle_logout_get_request(myHttpHandler, partial_path)
    elif partial_path.startswith('/register/'):
        partial_path = partial_path.replace('/register', '')
        handle_register_get_request(myHttpHandler, partial_path)
    elif partial_path.startswith('/profile/'):
        partial_path = partial_path.replace('/profile', '')
        handle_profile_get_request(myHttpHandler, partial_path)
    else:
        myHttpHandler.return_404()


def handle_login_get_request(db_connection, myHttpHandler, partial_path):
    myHttpHandler.set_headers(HTTPStatus.OK, main.get_default_headers())
    try:
        with open('html/login.html', 'r') as content_file:
            content = content_file.read()
    except:
        return myHttpHandler.return_server_error()
    response = str(content)
    response_in_bytes = bytearray(response, "utf-8")
    myHttpHandler.wfile.write(response_in_bytes)


def handle_logout_get_request(db_connection, myHttpHandler, partial_path):
    cookie_header = str(myHttpHandler.headers['Cookie'])
    cookie = utility_functions.get_cookie_value_from_cookie_header(cookie_header)
    if cookie == None or not main.authenticated_users.get(cookie):
        return myHttpHandler.set_headers(HTTPStatus.TEMPORARY_REDIRECT, main.get_redirect_headers('/'))
    myHttpHandler.set_headers(HTTPStatus.OK, main.get_default_headers())
    try:
        with open('html/logout.html', 'r') as content_file:
            content = content_file.read()
    except:
        return myHttpHandler.return_server_error()
    response = str(content)
    response_in_bytes = bytearray(response, "utf-8")
    myHttpHandler.wfile.write(response_in_bytes)


def handle_register_get_request(db_connection, myHttpHandler, partial_path):
    myHttpHandler.set_headers(HTTPStatus.OK, main.get_default_headers())
    try:
        with open('html/register.html', 'r') as content_file:
            content = content_file.read()
    except:
        return myHttpHandler.return_server_error()
    response = str(content)
    response_in_bytes = bytearray(response, "utf-8")
    myHttpHandler.wfile.write(response_in_bytes)


def handle_profile_get_request(db_connection, myHttpHandler, partial_path):
    cookie_header = str(myHttpHandler.headers['Cookie'])
    cookie = utility_functions.get_cookie_value_from_cookie_header(cookie_header)
    user_id = authenticated_users.get(cookie)
    if not user_id:
        return myHttpHandler.set_headers(HTTPStatus.TEMPORARY_REDIRECT, main.get_redirect_headers('/accounts/login/'))

    user = models.get_user_from_database(db_connection, user_id)
    if not user:
        return myHttpHandler.set_headers(HTTPStatus.TEMPORARY_REDIRECT, main.get_redirect_headers('/accounts/login/'))
    myHttpHandler.set_headers(HTTPStatus.OK, main.get_default_headers())
    print(user)
    try:
        with open('html/profile.html', 'r') as content_file:
            content = content_file.read()
    except:
        return myHttpHandler.return_server_error()
    # response =content
    response = utility_functions.put_var_in_html(content, 'name', user[0]['firstname'])
    response_in_bytes = bytearray(response, "utf-8")
    myHttpHandler.wfile.write(response_in_bytes)


# post request method
def handle_accounts_post_request(db_connection, myHttpHandler, partial_path):
    if partial_path.startswith('/login/') or partial_path.endswith('/login'):
        partial_path = partial_path.replace('/login', '')
        handle_login_post_request(myHttpHandler, partial_path)
    elif partial_path.startswith('/logout/'):
        partial_path = partial_path.replace('/logout', '')
        handle_logout_post_request(myHttpHandler, partial_path)
    elif partial_path.startswith('/register/'):
        partial_path = partial_path.replace('/register', '')
        handle_register_post_request(myHttpHandler, partial_path)
    else:
        myHttpHandler.return_404()


def handle_login_post_request(db_connection, myHttpHandler, partial_path):
    ctype, pdict = cgi.parse_header(myHttpHandler.headers['content-type'])
    if ctype == 'multipart/form-data':
        postvars = cgi.parse_multipart(myHttpHandler.rfile, pdict)
    elif ctype == 'application/x-www-form-urlencoded':
        length = int(myHttpHandler.headers['content-length'])
        postvars = urllib_parse.parse_qs(myHttpHandler.rfile.read(length), keep_blank_values=1)
    else:
        postvars = {}
    for key in postvars.keys():
        if key.decode('ascii') == 'username':
            username = postvars.get(key)
        if key.decode('ascii') == 'password':
            password = postvars.get(key)
    username = username[0]
    password = password[0]

    #  user name or password not provided in request
    if username == None or password==None :
        return handle_login_get_request(myHttpHandler, partial_path)
    username = username.decode('ascii')
    password = password.decode('ascii')
    user = models.check_username_password(db_connection, username, password)

    #  wrong credentials
    if not user:
        return handle_login_get_request(myHttpHandler, partial_path)

    # successful login
    user_id = user[0]['id']
    cookie = main.get_user_cookie(user_id)

    if not cookie:
        cookie= main.get_new_cookie_number()
        print('auth before add :' + str(main.authenticated_users))
        main.add_user_to_authenticated_users(cookie,user_id)
    myHttpHandler.set_headers(HTTPStatus.TEMPORARY_REDIRECT, main.get_login_headers(cookie))


def handle_logout_post_request(db_connection, myHttpHandler, partial_path):
    myHttpHandler.set_headers(HTTPStatus.TEMPORARY_REDIRECT, main.get_logout_headers())
    cookie_header = str(myHttpHandler.headers['Cookie'])
    cookie = utility_functions.get_cookie_value_from_cookie_header(cookie_header)
    main.delete_cookie_from_authenticated_users(cookie)


def handle_register_post_request(db_connection, myHttpHandler, partial_path):
    cookie_header = str(myHttpHandler.headers['Cookie'])
    cookie = utility_functions.get_cookie_value_from_cookie_header(cookie_header)
    user_id = authenticated_users.get(cookie)
    if user_id:
        return myHttpHandler.set_headers(HTTPStatus.TEMPORARY_REDIRECT, main.get_redirect_headers('/'))

    ctype, pdict = cgi.parse_header(myHttpHandler.headers['content-type'])
    if ctype == 'multipart/form-data':
        postvars = cgi.parse_multipart(myHttpHandler.rfile, pdict)
    elif ctype == 'application/x-www-form-urlencoded':
        length = int(myHttpHandler.headers['content-length'])
        postvars = urllib_parse.parse_qs(myHttpHandler.rfile.read(length), keep_blank_values=1)
    else:
        postvars = {}
    for key in postvars.keys():
        if key.decode('ascii') == 'username':
            username = postvars.get(key)
        if key.decode('ascii') == 'firstname':
            firstname = postvars.get(key)
        if key.decode('ascii') == 'password':
            password = postvars.get(key)
        if key.decode('ascii') == 'password2':
            password2 = postvars.get(key)

    username = username[0]
    firstname = firstname[0]
    password = password[0]
    password2 = password2[0]

    username = username.decode('ascii')
    password = password.decode('ascii')
    firstname = firstname.decode('ascii')
    password2 = password2.decode('ascii')

    if username==None or password==None or password2==None:
        print('not all of the fields were filled')
        return handle_register_get_request(myHttpHandler, partial_path)

    if models.search_user_by_username(db_connection, username):
        print('username already exists')
        return handle_register_get_request(myHttpHandler, partial_path)

    if password != password2:
        print('passwords dont match')
        return handle_register_get_request(myHttpHandler, partial_path)

    models.save_user_to_database(db_connection, username, password, firstname)
    myHttpHandler.set_headers(HTTPStatus.TEMPORARY_REDIRECT, main.get_redirect_headers('/'))
