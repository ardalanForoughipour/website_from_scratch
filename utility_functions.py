import random
from http import cookies
import main
import bleach


def put_var_in_html(inputHtml, varname, value):
    toReplace = '%'+str(varname)+'%'
    result = inputHtml.replace(toReplace, bleach.clean(str(value)))
    return result


def get_cookie_value_from_cookie_header(cookie_header):
    if not cookie_header:
        return None
    start_index = cookie_header.find('SID')
    end_index = cookie_header.find(';',start_index)
    if end_index == -1:
        end_index = len(cookie_header)
    user_cookie = cookie_header[start_index:end_index]
    start_index = user_cookie.find('=')
    user_cookie = user_cookie[start_index + 1:end_index]
    return user_cookie


def put_news_in_html(inputHtml,varname,news):
    toReplace = '%' + str(varname) + '%'
    replaceWith = ''
    for n in news:
        html_item_code = '<div><h4>'+bleach.clean(str(n['title']))+'</h4><p>'+bleach.clean(str(n['article']))+'</p><hr></div>'
        replaceWith = replaceWith + html_item_code
    result = inputHtml.replace(toReplace, replaceWith)
    return result


def put_news_detail_in_html(inputHtml,varname,the_news,uploader):
    toReplace = '%' + str(varname) + '%'
    replaceWith = ''
    html_item_code = '<div><h4>'+bleach.clean(str(the_news['title']))+\
                     '</h4><p>'+bleach.clean(str(the_news['article']))+\
                     '</p><hr><p>by :'+ \
                     bleach.clean(str(uploader['username']))+'</p></div>'
    replaceWith = replaceWith + html_item_code
    result = inputHtml.replace(toReplace, replaceWith)
    return result


def remove_unused_variables_in_html(inputHtml):
    # todo
    pass