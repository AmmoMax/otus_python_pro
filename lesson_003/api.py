#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

class CommonField:
    """Базовый класс для всех классов полей-дескрипторов."""
    def __init__(self, required):
        self.required = required

    def __set_name__(self, owner, name):
        self.pub_attr_name = name
        self.priv_attr_name = "_" + name

    def __set__(self, instance, value):
        setattr(instance, self.priv_attr_name, value)

    def __get__(self, instance, owner):
        res = getattr(instance, self.priv_attr_name)
        return res


class CharField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable


class ArgumentsField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable


class EmailField(CharField):
    pass


class PhoneField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable


class DateField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable


class BirthDayField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable


class GenderField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable


class ClientIDsField(CommonField):
    pass


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(object):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, first_name, last_name, email, phone, birthday, gender):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.birthday = birthday
        self.gender = gender

    def get_score(self):
        self.score = 0
        if self.phone:
            self.score += 1.5
        if self.email:
            self.score += 1.5
        if self.birthday and self.gender:
            self.score += 1.5
        if self.first_name and self.last_name:
            self.score += 0.5
        return self.score


class MethodRequest(object):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, account, login, token, arguments, method):
        self.account = account
        self.login = login
        self.token = token
        self.arguments = arguments
        self.method = method

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def online_score_handler(request, ctx, store):
    #
    body = request['body']
    arguments = body['arguments']
    client_request = OnlineScoreRequest(**arguments)

    response = {'score': client_request.get_score()}
    code = 200

    return response, code


def method_handler(request, ctx, store):
    """Вызывает нужный обработчик для входящего метода в зависимости от запроса.

    В теле запроса передается имя метода в ключе 'method'
    Пример:  method: online_score
    """
    method = request['body']['method']
    handlers_list = {'online_score': online_score_handler}
    try:
        response, code = handlers_list[method](request, ctx, store)
    except KeyError:
        response = 'Method not found'
        code = 404
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
