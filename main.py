import cgi
import datetime
import os

import random as random
import random as random_csrf_creator

import re
from http import cookies
from http.cookiejar import Cookie
from urllib import parse as urllib_parse
import ssl
from http import HTTPStatus, cookiejar
from http.server import HTTPServer, BaseHTTPRequestHandler


import accounts
import news

authenticated_users = {}
cookie_headers = {}
cookie_csrf = {}


max_file_name_length = 100


# min_file_size_in_bytes = 100
max_file_size_in_bytes = 512300 # 500KB + 300bytes for http stuff


def create_and_add_cookie_header_deatails(cookie, cookie_header):
    print(cookie)
    print(cookie_header)
    cookie_headers[str(cookie)] = str(cookie_header)


def create_and_add_csrf_token(cookie):
    random_csrf_creator.seed(cookie)
    csrf_token = random_csrf_creator.randrange(111111111, 999999999)
    while csrf_token in cookie_csrf.values():
        csrf_token = random_csrf_creator.randrange(111111111, 999999999)
    cookie_csrf[str(cookie)] = csrf_token


def is_in_blacklist_file_name(fn):
    if not all(x.isalpha() or x.isalnum() or x.isspace() or x == '.' for x in fn):
        return True
    if str(fn).count('.') != 1:
        return True
    if fn == '':
        return True
    if fn == 'CON':
        return True
    if fn == 'PRN':
        return True
    if fn == 'AUX':
        return True
    if fn == 'NUL':
        return True
    if fn == 'COM1':
        return True
    if fn == 'COM2':
        return True
    if fn == 'COM3':
        return True
    if fn == 'COM4':
        return True
    if fn == 'COM5':
        return True
    if fn == 'COM6':
        return True
    if fn == 'COM7':
        return True
    if fn == 'COM8':
        return True
    if fn == 'COM9':
        return True
    if fn == 'LPT1':
        return True
    if fn == 'LPT2':
        return True
    if fn == 'LPT3':
        return True
    if fn == 'LPT4':
        return True
    if fn == 'LPT5':
        return True
    if fn == 'LPT6':
        return True
    if fn == 'LPT7':
        return True
    if fn == 'LPT8':
        return True
    if fn == 'LPT9':
        return True
    return False


def validate(file_name, file_type , file_size):
    if len(file_name) > max_file_name_length :
        return False
    if is_in_blacklist_file_name(file_name):
        return False
    if int(file_size) > max_file_size_in_bytes:
        return False
    file_extension = file_name[file_name.rfind('.'):len(file_name)]
    if not (file_type == 'text/plain' or (file_type == 'application/x-rar' and file_extension == '.rar')):
        return False
    return True


def delete_cookie_from_authenticated_users(cookie):
    authenticated_users.pop(str(cookie))
    cookie_headers.pop(str(cookie))


def get_user_cookie(user_id):
    for k in authenticated_users.keys():
        if authenticated_users.get(k) == str(user_id):
            return k
    return None


def add_user_to_authenticated_users(cookie, id):
    # print('new cookie : '+ str(cookie))
    if not get_user_cookie(id):
        authenticated_users[str(cookie)] = str(id)
        create_and_add_csrf_token(cookie)
    # print('auth users after add: ' + str(authenticated_users))


def get_new_cookie_number():
    new_cookie = random.randint(111111,999999)
    while new_cookie in authenticated_users.keys():
        new_cookie = random.randint(111111, 999999)
    return new_cookie


# create header functions

def get_default_headers():
    h1 = ['Content-type', 'text/html']
    return [h1]


def get_redirect_headers(redirectPath):
    result = get_default_headers()
    result.append(['location', str(redirectPath)])
    return result


def get_login_headers(cookie):
    result = get_redirect_headers('/')
    c = cookies.SimpleCookie()
    c['SID'] = str(cookie)
    c['SID']["path"] = '/'
    expires = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    c['SID']['expires'] = expires
    header_value = str(c).replace("Set-Cookie: ", '')
    create_and_add_cookie_header_deatails(cookie, header_value)
    result.append(['Set-Cookie', header_value])
    return result


def get_logout_headers():
    result = get_redirect_headers('/')
    c = cookies.SimpleCookie()
    c['SID'] = str('000000')
    c['SID']["path"] = '/'
    tow_str = '52300'
    expires = datetime.datetime.strptime(tow_str, "%w%H%M")
    c['SID']['expires'] = expires
    header_value = str(c).replace("Set-Cookie: ", '')
    result.append(['Set-Cookie', header_value])
    return result


class MyHttpRequestHandler(BaseHTTPRequestHandler):

    def handle_file_upload(self):
        content_type = self.headers['content-type']
        if not content_type:
            return (False, "Content-Type header doesn't contain boundary")
        boundary = content_type.split("=")[1].encode()
        remainbytes = int(self.headers['content-length'])
        line = self.rfile.readline()
        remainbytes -= len(line)
        if not boundary in line:
            return (False, "Content NOT begin with boundary")
        line = self.rfile.readline()
        remainbytes -= len(line)
        fn = re.findall(r'Content-Disposition.*name="file"; filename="(.*)"', line.decode())
        if not fn:
            return (False, "Can't find out file name...")
        fn = fn[0]

        line = self.rfile.readline()
        ft = str(line)[str(line).find(':') + 1:len(line)].strip()
        remainbytes -= len(line)
        fs = self.headers['Content-Length']
        if not validate(fn, ft,fs):
            return (False, "Unsafe file")

        path = os.getcwd()
        path = os.path.join(path, 'uploads')
        filePath = os.path.join(path, fn)

        line = self.rfile.readline()
        print(line)
        remainbytes -= len(line)
        try:
            out = open(filePath, 'wb')
        except IOError:
            return (False, "Can't create file to write, do you have permission to write?")

        preline = self.rfile.readline()

        remainbytes -= len(preline)
        while remainbytes > 0:
            line = self.rfile.readline()
            remainbytes -= len(line)
            if boundary in line:
                preline = preline[0:-1]
                if preline.endswith(b'\r'):
                    preline = preline[0:-1]
                out.write(preline)
                out.close()
                return (True, "File '%s' upload success!" % fn)
            else:
                out.write(preline)
                preline = line
        return (False, "Unexpect Ends of data.")

    def set_headers(self, code, headers):
        self.send_response(code)
        for header in headers:
            self.send_header(header[0], header[1])
        self.send_header('Content-Security-Policy', " frame-ancestors 'none'")
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()

    def return_404(self):
        self.set_headers(HTTPStatus.NOT_FOUND, [])
        response = "<html><body><h1>Error 404</h1><p>page not found</p></body></html>"
        response_in_bytes = bytearray(response, "utf-8")
        self.wfile.write(response_in_bytes)

    def return_server_error(self):
        self.set_headers(HTTPStatus.INTERNAL_SERVER_ERROR, get_default_headers())
        response = "<html><body><h1>internal server error</h1></body></html>"
        response_in_bytes = bytearray(response, "utf-8")
        self.wfile.write(response_in_bytes)

    def return_invalid_file_page(self):
        self.set_headers(HTTPStatus.OK, get_default_headers())
        response = """<html><body><h1>invalid file</h1><a href="/file/upload/">upload file</a></body></html>"""
        response_in_bytes = bytearray(response, "utf-8")
        self.wfile.write(response_in_bytes)

    def do_GET(self):
        # Extract values from the query string
        raw_path, _, query_string = self.path.partition('?')
        if raw_path.startswith('/accounts/'):
            partial_path = raw_path.replace('/accounts', '')
            accounts.handle_accounts_get_request(self, partial_path)
            return

        if raw_path.startswith('/news/'):
            partial_path = raw_path.replace('/news', '')
            news.handle_news_get_request(self,partial_path)
            return

        # if raw_path.startswith('/test'):
        #     import test
        #     return test.test_handler(self,None)
        if raw_path.startswith("/file/upload"):
            self.set_headers(HTTPStatus.OK, get_default_headers())
            try:
                with open('html/fileUploadPage.html', 'r') as content_file:
                    content = content_file.read()
            except:
                return self.return_server_error()
            response = str(content)
            response_in_bytes = bytearray(response, "utf-8")
            self.wfile.write(response_in_bytes)
            return

        if raw_path == '/':
            #return home page
            self.set_headers(HTTPStatus.OK, get_default_headers())
            try:
                with open('html/index.html', 'r') as content_file:
                    content = content_file.read()
            except:
                return self.return_server_error()
            response = str(content)
            response_in_bytes = bytearray(response, "utf-8")
            self.wfile.write(response_in_bytes)
        else:
            self.return_404()

    def do_HEAD(self):
        self.set_headers(HTTPStatus.OK,get_default_headers())

    def do_POST(self):
        # Extract values from the query string
        raw_path, _, query_string = self.path.partition('?')
        if raw_path.startswith('/accounts/'):
            partial_path = raw_path.replace('/accounts', '')
            accounts.handle_accounts_post_request(self, partial_path)
            return

        if raw_path.startswith('/news/'):
            partial_path = raw_path.replace('/news', '')
            news.handle_news_post_request(self,partial_path)
            return

        if raw_path.startswith("/file/upload"):
            r, info = self.handle_file_upload()
            if not r:
                if info == 'Unsafe file':
                    self.return_invalid_file_page()
                    print('Unsafe file')
                    return
                self.return_server_error()
                print(info)
                return

            self.set_headers(HTTPStatus.OK, get_default_headers())
            try:
                with open('html/fileUploadPage.html', 'r') as content_file:
                    content = content_file.read()
            except Exception as e:
                print(e)
                return self.return_server_error()
            response = str(content)
            response_in_bytes = bytearray(response, "utf-8")
            self.wfile.write(response_in_bytes)
            return

        if raw_path == '/':
            #return home page
            self.set_headers(HTTPStatus.OK,get_default_headers())
            try:
                with open('html/index.html', 'r') as content_file:
                    content = content_file.read()
            except:
                return self.return_server_error()
            response = str(content)
            response_in_bytes = bytearray(response, "utf-8")
            self.wfile.write(response_in_bytes)
        else:
            self.return_404()


def run(server_class=HTTPServer, handler_class=MyHttpRequestHandler):
    try:
        server_address = ('127.0.0.1', 8000)
        httpd = server_class(server_address, handler_class)
        server_class.socket = ssl.wrap_socket(server_class.socket, keyfile="./server.pem", certfile='./server.pem', server_side =True)
        httpd.serve_forever()
    except KeyboardInterrupt:
        # A request to terminate has been received, stop the server
        print("\nShutting down...")


if __name__ == '__main__':
    try:
        server_address = ('127.0.0.1', 8000)
        httpd = HTTPServer(server_address, MyHttpRequestHandler)
        # httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="./server.pem", certfile='./server.pem', server_side=True)
        httpd.serve_forever()
    except KeyboardInterrupt:
        # A request to terminate has been received, stop the server
        print("\nShutting down...")


