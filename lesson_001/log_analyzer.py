#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import argparse
import configparser
import dataclasses
import datetime
import functools
import gzip
import logging
import os
import re
import statistics
import sys
import tempfile
import time
import unittest
from collections import namedtuple, defaultdict, Counter
from pathlib import Path
from string import Template
from typing import Generator, List


def micro_time_counter(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        func(*args, **kwargs)
        logging.debug(f'We did it for : {time.perf_counter() - start_time:.3}s')
    return wrapper


def find_latest_logfile(log_dir: str) -> namedtuple:
    """
    Находит самый свежий файл с логом nginx.
    :param log_dir: путь к папке с логами
    :return: Возвращает namedtuple типа ActualLogFile c полями path, delta, date
    """
    file_date_reg = r'\d{4}\d{2}\d{2}|\.gz'
    file_name_pattern = re.compile(file_date_reg)
    log_dir_path = Path(log_dir).glob("**/*")
    files = [file for file in log_dir_path if file.is_file()]
    res_log_files = []
    now = datetime.datetime.now().date()

    logging.info(f'Looking for the latest file on the path: {log_dir}')

    if not files:
        logging.error(f'Have no log files on the path: {log_dir}')
        raise FileNotFoundError(f'Have no log files on the path: {log_dir}')

    for file in files:
        match = file_name_pattern.findall(file.name)
        if match:
            ActualLogFile = namedtuple('ActualLogFile', ['path', 'delta', 'date'])
            file_datetime = datetime.datetime.strptime(match[0], "%Y%m%d").date()
            delta = now - file_datetime
            ActualLogFile.path = file.as_posix()
            ActualLogFile.delta = delta.days
            ActualLogFile.date = datetime.datetime.strptime(match[0], '%Y%m%d')
            res_log_files.append(ActualLogFile)
    latest = min(res_log_files, key=lambda x: x.delta)
    logging.info(f'Find latest log file on the path: {log_dir}. File name: {latest.path}')
    return latest


def read_log_line(log_path: str) -> Generator:
    """Читает построчно лог и возвращает генератор c url и req_time"""
    error_line_counter = 0
    total_line_counter = 0
    # допустимый порог ошибок парсинг лога
    ERROR_THRESHOLD = 0.2

    with(gzip.open(log_path, 'rb') if log_path.endswith('gz') else open(log_path)) as file:
        for common_line in file:
            log_parts = common_line.split(' ')
            url = log_parts[7]
            req_time = log_parts[-1]

            url_reg = re.compile(r'^\/([a-zA-Z0-9]+\/)*([^\s])+')
            req_time_reg = re.compile(r'\d\.\d+')

            if not re.fullmatch(url_reg, url) and not re.fullmatch(req_time_reg, req_time):
                error_line_counter += 1
                continue
            total_line_counter += 1
            yield url, req_time

    parsing_errors = error_line_counter / total_line_counter
    if parsing_errors > ERROR_THRESHOLD:
        logging.error(f'Error threshold: {ERROR_THRESHOLD} exceeded. Stop parsing and exit!')
        raise EOFError('Error threshold exceeded!')


def prepare_data_for_report(log_parser: Generator, report_size: int) -> list:
    """Собирает структуру для отчета.
    Возвращает список из словарей. В каждом словаре собрана статистика по каждому url
    Пример:
    [{"count": 2767, "time_avg": 62.994999999999997,
    "time_max": 9843.5689999999995, "time_sum": 174306.35200000001,
    "url": "/api/v2/internal/html5/phantomjs/queue/?wait=1m", "time_med": 60.073,
    "time_perc": 9.0429999999999993, "count_perc": 0.106}]
    """
    all_req_time = 0
    report_dict = defaultdict(dict)
    for url, request_time in log_parser:
        request_time = float(request_time)
        current_url = report_dict[url]
        if not current_url:
            report_dict[url].update({'count': Counter({url: 1})})
            report_dict[url].update({'req_time': [request_time]})
        else:
            report_dict[url]['count'].update((url,))
            report_dict[url]['req_time'].append(request_time)
        all_req_time += request_time

    common_request_count = len(report_dict.keys())

    report_list = list()
    for url, data in report_dict.items():
        req_time_list = data['req_time']
        time_sum = sum(req_time_list)
        current_url_data = {
            'url': url,
            'count': data['count'][url],
            'time_sum': time_sum,
            'time_avg': time_sum / len(req_time_list),
            'time_max': max(req_time_list),
            'time_med': statistics.median(req_time_list),
            'count_perc': data['count'][url] / common_request_count * 100,
            'time_perc': time_sum / all_req_time * 100
        }
        report_list.append(current_url_data)
    report_list.sort(key=lambda url_report: url_report['time_max'], reverse=True)
    return report_list[:report_size]


def get_config():
    """Возвращает конфиг либо полученный в аргументах при запуске, либо по-умолчанию"""

    @dataclasses.dataclass
    class DefaultConfig:
        REPORT_SIZE: int = 10
        REPORT_DIR: str = "./reports"
        LOG_DIR: str = "./log"

        def __post_init__(self):
            # потому что параметры в ini конфиге читаются как строки
            self.REPORT_SIZE = int(self.REPORT_SIZE)

    logging.info(f'Getting config...')

    parser = argparse.ArgumentParser(description='Parse and generate report for nginx latest log.')
    parser.add_argument('--config', help='Path to .ini config file', required=False)
    args = parser.parse_args()

    config = configparser.ConfigParser()
    if args.config:
        if not os.path.exists(args.config):
            logging.error(f'Config file not found by path: {args.config}')
            raise FileNotFoundError(f'Config file not found by path: {args.config}')

        config.read(args.config)

        try:
            common_config = DefaultConfig(**{k.upper(): v for k, v in config['config_params'].items()})
        except KeyError as error:
            logging.error(f'It is not valid config file! RTFM please! Error: {error}')
            raise
    else:
        common_config = DefaultConfig()
    logging.info(f'Config received: {common_config.__dict__}')
    return common_config


def build_report(report_data: List[dict], report_date: datetime, report_path: str, report_template: str='report.html'):
    """Создает и заполняет файл отчета из html шаблона"""
    logging.info(f'Building report...')

    with open(report_template) as file:
        report_file = file.read()
    s = Template(report_file)
    final_report = s.safe_substitute(table_json=report_data)
    report_name = f'report-{report_date.strftime("%Y.%m.%d")}.html'
    final_report_path = Path(report_path).joinpath(report_name)
    if not os.path.isfile(final_report_path):
        os.makedirs(report_path, exist_ok=True)
        with open(str(final_report_path), 'w') as file:
            file.write(final_report)
        logging.info(f'Report file was create. You can find it on the path: {final_report_path}')
    else:
        logging.info(f'Report file {report_name} has already exist to path {final_report_path}')


def check_report_exist(report_date: datetime, report_path: str):
    """Проверяет существование отчета по дате"""
    report_name = f'report-{report_date.strftime("%Y.%m.%d")}.html'
    final_report_path = Path(report_path).joinpath(report_name)
    return os.path.isfile(final_report_path)

### STARTING TESTS
class FindLatestLogfileTestCase(unittest.TestCase):
    """Тест кейсы для функции find_latest_logfile"""
    def test_return_tuple_existing_fields(self):
        """Проверяет наличие полей у path, delta, date в результате выполнения функции"""
        real_log_file_path = './log'
        res_tuple = find_latest_logfile(real_log_file_path)
        self.assertTrue(hasattr(res_tuple, 'path'))
        self.assertTrue(hasattr(res_tuple, 'delta'))
        self.assertTrue(hasattr(res_tuple, 'date'))

    def test_not_existing_file_path(self):
        """Проверяет что возвращается исключение FileNotFound в случае если по пути нет файлов с логами"""
        real_log_file_path = './test_log'
        self.assertRaises(FileNotFoundError, find_latest_logfile, real_log_file_path)

class ReadLogFileTestCase(unittest.TestCase):
    """Тест-кейсы для функции read_log_line"""
    @classmethod
    def setUpClass(cls) -> None:
        """Создает временный файл с валидным логом для теста"""
        cls.log_file_str = """1.195.44.0 -  - [30/Jun/2017:03:27:11 +0300] "GET /api/v2" 200 12 "-" "-" "-" "1498782431-1775774396-4709-10705639" "0d9e6ca2ba" 0.158"""
        cls.tmp_log_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        cls.tmp_log_file.write(cls.log_file_str)
        cls.tmp_log_file.close()

    @classmethod
    def tearDownClass(cls) -> None:
        os.remove(cls.tmp_log_file.name)

    def test_read_one_correct_str(self):
        """Проверяет корректность формата прочитанной строки"""
        res_gen = read_log_line(self.tmp_log_file.name)
        log_file_parts = self.log_file_str.split(' ')
        for url, req_time in res_gen:
            self.assertTrue(url == log_file_parts[7])
            self.assertTrue(req_time == log_file_parts[-1])



### ENDING TEST

@micro_time_counter
def main():
    format = '[%(asctime)s] %(levelname).1s %(message)s'
    logging.basicConfig(format=format, level=logging.DEBUG, datefmt='%Y.%m.%d %H:%M:%S')

    logging.debug(f'Starting to parse file!')
    try:
        config = get_config()

        latest_log = find_latest_logfile(config.LOG_DIR)
        if not check_report_exist(latest_log.date, config.REPORT_DIR):
            lines = read_log_line(latest_log.path)
            report_data = prepare_data_for_report(lines, config.REPORT_SIZE)
            build_report(report_data, latest_log.date, config.REPORT_DIR)
        else:
            logging.info(f'Report for latest log is existing. Try to see in {config.REPORT_DIR}')
    except (FileNotFoundError, EOFError):
        sys.exit(1)

if __name__ == "__main__":
    main()