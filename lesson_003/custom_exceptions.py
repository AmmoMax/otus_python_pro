"""
Модуль содержит кастомные исключения для проекта.
Например ошибки валидации полей запроса.
"""


class FieldValidationError(Exception):
    def __init__(self, msg):
        self.msg = msg