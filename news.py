import cgi
from http import HTTPStatus
from urllib import parse as urllib_parse
import main
import models
import utility_functions


def handle_news_get_request(myHttpHandler, partial_path):
    if partial_path.startswith('/all/') or partial_path.endswith('/all'):
        partial_path = partial_path.replace('/all', '')
        handle_see_all_news_get_request(myHttpHandler, partial_path)

    elif partial_path.startswith('/add/') or partial_path.endswith('/add'):
        partial_path = partial_path.replace('/add', '')
        handle_add_news_get_request(myHttpHandler, partial_path)

    elif partial_path.startswith('/edit/'):
        partial_path = partial_path.replace('/edit', '')
        handle_edit_news_get_request(myHttpHandler, partial_path)

    elif partial_path.startswith('/code/'):
        partial_path = partial_path.replace('/code', '')
        handle_see_news_detail_get_request(myHttpHandler, partial_path)
    else:
        myHttpHandler.return_404()


# handling http get methods
def handle_see_all_news_get_request(myHttpHandler,partial_path):
    news = models.get_all_news()
    myHttpHandler.set_headers(HTTPStatus.OK, main.get_default_headers())
    try:
        with open('html/allnews.html', 'r') as content_file:
            content = content_file.read()
    except:
        return myHttpHandler.return_server_error()
    response = str(content)
    response = utility_functions.put_news_in_html(response, 'allnews', news)
    response_in_bytes = bytearray(response, "utf-8")
    myHttpHandler.wfile.write(response_in_bytes)


def handle_see_news_detail_get_request(myHttpHandler,partial_path):
    try :
        pk_url = partial_path[1:partial_path.index('/',1)]
    except:
        pk_url = partial_path[1:len(partial_path)]

    try :
        news_id = int(pk_url)
    except:
        return myHttpHandler.return_404()

    the_news = models.get_a_news_from_database(news_id)
    if not the_news:
        return myHttpHandler.return_404()
    the_news = the_news[0]
    uploader = models.get_user_from_database(the_news['user_id'])[0]
    myHttpHandler.set_headers(HTTPStatus.OK, main.get_default_headers())
    try:
        with open('html/news_details.html', 'r') as content_file:
            content = content_file.read()
    except:
        return myHttpHandler.return_server_error()
    response = str(content)
    response = utility_functions.put_news_detail_in_html(response,'newsdetail',the_news,uploader)
    response_in_bytes = bytearray(response, "utf-8")
    myHttpHandler.wfile.write(response_in_bytes)


def handle_edit_news_get_request(myHttpHandler,partial_path):
    # if user is logged in
    cookie_header = str(myHttpHandler.headers['Cookie'])
    cookie = utility_functions.get_cookie_value_from_cookie_header(cookie_header)
    user_id = main.authenticated_users.get(cookie)
    if not user_id:
        print('user not logged in')
        return myHttpHandler.return_404()
    # if pk is valid
    try:
        pk_url = partial_path[1:partial_path.index('/', 1)]
    except:
        pk_url = partial_path[1:len(partial_path)]

    try:
        news_id = int(pk_url)
    except:
        print('invalid url')
        return myHttpHandler.return_404()

    the_news = models.get_a_news_from_database(news_id)
    if not the_news:
        print('invalid pk number')
        return myHttpHandler.return_404()
    the_news = the_news[0]
    # if user is the creator of the post
    if str(the_news['user_id']) != user_id:
        return myHttpHandler.return_404()
    # user is ok so continue
    myHttpHandler.set_headers(HTTPStatus.OK, main.get_default_headers())
    try:
        with open('html/editnews.html', 'r') as content_file:
            content = content_file.read()
    except:
        return myHttpHandler.return_server_error()
    response = str(content)
    response = utility_functions.put_var_in_html(response, 'titleVal', the_news['title'])
    response = utility_functions.put_var_in_html(response, 'articleVal', the_news['article'])
    response = utility_functions.put_var_in_html(response, 'csrf_token', main.cookie_csrf[cookie])
    response_in_bytes = bytearray(response, "utf-8")
    myHttpHandler.wfile.write(response_in_bytes)


def handle_add_news_get_request(myHttpHandler,partial_path):
    cookie_header = str(myHttpHandler.headers['Cookie'])
    cookie = utility_functions.get_cookie_value_from_cookie_header(cookie_header)
    test = main.authenticated_users
    user_id = main.authenticated_users.get(cookie)
    if not user_id:
        return myHttpHandler.return_404()
    myHttpHandler.set_headers(HTTPStatus.OK, main.get_default_headers())
    try:
        with open('html/addnews.html', 'r') as content_file:
            content = content_file.read()
    except:
        return myHttpHandler.return_server_error()
    response = str(content)
    response = utility_functions.put_var_in_html(response, 'csrf_token', main.cookie_csrf[cookie])
    response_in_bytes = bytearray(response, "utf-8")
    myHttpHandler.wfile.write(response_in_bytes)


# handeling http post methods
def handle_news_post_request(myHttpHandler, partial_path):
    if partial_path.startswith('/add/') or partial_path.endswith('/add'):
        partial_path = partial_path.replace('/add', '')
        handle_add_news_post_request(myHttpHandler, partial_path)

    elif partial_path.startswith('/edit/'):
        partial_path = partial_path.replace('/edit', '')
        handle_edit_news_post_request(myHttpHandler, partial_path)
    else:
        myHttpHandler.return_404()


def handle_edit_news_post_request(myHttpHandler,partial_path):
    # if user is logged in
    cookie_header = str(myHttpHandler.headers['Cookie'])
    cookie = utility_functions.get_cookie_value_from_cookie_header(cookie_header)
    user_id = main.authenticated_users.get(cookie)
    if not user_id:
        print('user not logged in')
        return myHttpHandler.return_404()
    # if pk is valid
    try:
        pk_url = partial_path[1:partial_path.index('/', 1)]
    except:
        pk_url = partial_path[1:len(partial_path)]

    try:
        news_id = int(pk_url)
    except:
        print('invalid url')
        return myHttpHandler.return_404()

    the_news = models.get_a_news_from_database(news_id)
    if not the_news:
        print('invalid pk number')
        return myHttpHandler.return_404()
    the_news = the_news[0]
    # if user is the creator of the post
    if str(the_news['user_id']) != user_id:
        return myHttpHandler.return_404()
    # user is ok so continue
    ctype, pdict = cgi.parse_header(myHttpHandler.headers['content-type'])
    if ctype == 'multipart/form-data':
        postvars = cgi.parse_multipart(myHttpHandler.rfile, pdict)
    elif ctype == 'application/x-www-form-urlencoded':
        length = int(myHttpHandler.headers['content-length'])
        postvars = urllib_parse.parse_qs(myHttpHandler.rfile.read(length), keep_blank_values=1)
    else:
        postvars = {}
    for key in postvars.keys():
        if key.decode('ascii') == 'title':
            title = postvars.get(key)
        if key.decode('ascii') == 'article':
            article = postvars.get(key)
        if key.decode('ascii') == 'csrf_token':
            submitted_csrf_token = postvars.get(key)

    # cheking the csrf token for the user

    if (not submitted_csrf_token) or (not submitted_csrf_token[0]):
        print("csrf token was not submitted")
        return myHttpHandler.return_404()

    csrf_token = main.cookie_csrf[cookie]
    if not csrf_token:
        print("no registered csrf token for the sent cookie")
        return myHttpHandler.return_404()

    submitted_csrf_token = submitted_csrf_token[0]
    if not str(csrf_token) == str(submitted_csrf_token):
        print("wrong csrf token")
        return myHttpHandler.return_404()

    article = article[0]
    article = article.decode('ascii')
    title = title[0]
    title = title.decode('ascii')

    if title == None:
        print('title is empty')
        return handle_add_news_get_request(myHttpHandler, partial_path)
    r= models.check_title_exists(title)
    if r and r[0]:
        print('title exists')
        orig_id = str(r[0]['news_id'])
        if not orig_id == pk_url:
            return handle_add_news_get_request(myHttpHandler, partial_path)
        else:
            print("but it is ok because it is the title of this post")

    models.update_news_to_database(news_id,title,article)
    return myHttpHandler.set_headers(HTTPStatus.SEE_OTHER, main.get_redirect_headers('/news/all/'))


def handle_add_news_post_request(myHttpHandler,partial_path):
    cookie_header = str(myHttpHandler.headers['Cookie'])
    cookie = utility_functions.get_cookie_value_from_cookie_header(cookie_header)
    user_id = main.authenticated_users.get(cookie)
    if not user_id:
        return myHttpHandler.return_404()

    ctype, pdict = cgi.parse_header(myHttpHandler.headers['content-type'])
    if ctype == 'multipart/form-data':
        postvars = cgi.parse_multipart(myHttpHandler.rfile, pdict)
    elif ctype == 'application/x-www-form-urlencoded':
        length = int(myHttpHandler.headers['content-length'])
        postvars = urllib_parse.parse_qs(myHttpHandler.rfile.read(length), keep_blank_values=1)
    else:
        postvars = {}
    for key in postvars.keys():
        if key.decode('ascii') == 'title':
            title = postvars.get(key)
        if key.decode('ascii') == 'article':
            article = postvars.get(key)
        if key.decode('ascii') == 'csrf_token':
            submitted_csrf_token = postvars.get(key)


    # cheking the csrf token for the user
    if (not submitted_csrf_token) or (not submitted_csrf_token[0]):
        print("csrf token was not submitted")
        return myHttpHandler.return_404()

    csrf_token = main.cookie_csrf[cookie]
    if not csrf_token:
        print("no registered csrf token for the sent cookie")
        return myHttpHandler.return_404()

    submitted_csrf_token = submitted_csrf_token[0].decode('ascii')
    if not str(csrf_token) == str(submitted_csrf_token):
        print("wrong csrf token")
        return myHttpHandler.return_404()
    article = article[0].decode('ascii')
    title = title[0].decode('ascii')

    if title == None:
        print('title is empty')
        return handle_add_news_get_request(myHttpHandler,partial_path)
    if models.check_title_exists(title):
        print('title exists')
        return handle_add_news_get_request(myHttpHandler, partial_path)
    models.add_news_to_database(user_id,title,article)
    return myHttpHandler.set_headers(HTTPStatus.SEE_OTHER, main.get_redirect_headers('/news/all/'))

