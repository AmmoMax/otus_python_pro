#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import re
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
from time import strptime

from custom_exceptions import FieldValidationError

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

    def __set__(self, instance, value):
        if value and not isinstance(value, str):
            raise FieldValidationError(f'Field {self.pub_attr_name} must be str!')
        super().__set__(instance, value)


class ArgumentsField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable


class EmailField(CharField):

    def __set__(self, instance, value):
        if value is not None and "@" not in value:
            raise FieldValidationError("Email field doesn't contain '@'!")
        super().__set__(instance, value)


class PhoneField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable

    def __set__(self, instance, value):
        phone = re.compile(r'^7\d{10}')
        if value is not None and not phone.match(str(value)):
            raise FieldValidationError("Phone must starting with '7' and contain 11 symbols")
        super().__set__(instance, value)


class DateField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable


class BirthDayField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable

    def __set__(self, instance, value):
        date_fmt = "%d.%m.%Y"
        DAYS_IN_YEAR = 365.2425
        MAX_AGE = 70

        now = datetime.datetime.now()
        if value:
            try:
                birthday = datetime.datetime.strptime(value, date_fmt)
            except ValueError:
                raise FieldValidationError(f"Invalid {self.pub_attr_name} field. It must be in 'MM.DD.YYYY' format!")

            delta = now - birthday
            if delta.days / DAYS_IN_YEAR >= MAX_AGE:
                raise FieldValidationError(f"Invalid {self.pub_attr_name} field. You age should not be more than 70")
        super().__set__(instance, value)

class GenderField(CommonField):
    def __init__(self, required, nullable):
        super().__init__(required)
        self.nullable = nullable

    def __set__(self, instance, value):
        AVAILABLE_GENDERS_CODE = [0, 1, 2]
        if value and value not in AVAILABLE_GENDERS_CODE:
            raise FieldValidationError(f"Invalid field {self.pub_attr_name}. Available values: 0, 1, 2")
        super().__set__(instance, value)


class ClientIDsField(CommonField):
    pass


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest():

    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self,
                 first_name=None,
                 last_name=None,
                 email=None,
                 phone=None,
                 birthday=None,
                 gender=None):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.birthday = birthday
        self.gender = gender

        if not self.__validation_fields():
            raise FieldValidationError("Invalid number of fields! "
                                       "You must pass at least one pair of attrs: phone-email, first_name-last_name, gender-birthday")

    def __validation_fields(self):
        if (self.phone and self.email) is not None:
            return True
        if (self.first_name and self.last_name) is not None:
            return True
        if (self.gender and self.birthday) is not None:
            return True
        return False

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
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode('utf-8')).hexdigest()
    if digest == request.token:
        return True
    return False


def online_score_handler(request, ctx, store):

    body = request['body']
    arguments = body['arguments']
    method_request = MethodRequest(account=body['account'],
                                   login=body['login'],
                                   token=body['token'],
                                   arguments=arguments,
                                   method=body['method'])
    if not check_auth(method_request):
        return {'error': 'Forbidden'}, FORBIDDEN

    try:
        client_info = OnlineScoreRequest(**arguments)
        response = {'score': client_info.get_score()}
        code = OK
    except FieldValidationError as err:
        code = INVALID_REQUEST
        response = {'error': err.msg}
    return response, code


def method_handler(request, ctx, store):
    """Вызывает нужный обработчик для входящего метода в зависимости от запроса.

    В теле запроса передается имя метода в ключе 'method'
    Пример:  method: online_score
    """
    if not request['body']:
        return {'error': 'Empty request'}, INVALID_REQUEST

    method = request['body']['method']
    handlers_list = {'online_score': online_score_handler}
    try:
        response, code = handlers_list[method](request, ctx, store)
    except KeyError:
        response = 'Method not found'
        code = NOT_FOUND
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
