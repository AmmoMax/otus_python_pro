#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import datetime
import gzip
import re
import statistics
from collections import namedtuple, defaultdict, Counter
from pathlib import Path
from pprint import pprint
from typing import Generator

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log"
}



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

    for file in files:
        match = file_name_pattern.findall(file.name)
        if match:
            ActualLogFile = namedtuple('ActualLogFile', ['path', 'delta', 'date'])
            file_datetime = datetime.datetime.strptime(match[0], "%Y%m%d").date()
            delta = now - file_datetime
            ActualLogFile.path = file.as_posix()
            ActualLogFile.delta = delta.days
            ActualLogFile.date = match
            res_log_files.append(ActualLogFile)
    latest = min(res_log_files, key=lambda x: x.delta)
    return latest


def read_log_line(log_path: str):
    with(gzip.open(log_path, 'rb') if log_path.endswith('gz') else open(log_path)) as log:
        total_line = proceed = 0
        for line in log:
            yield line

def log_parser(log_line: Generator):
    """Парсит строку лога и возвращает url и request_time"""
    for line in log_line:
        log_parts = line.split(' ')
        # TODO: переделать поиск на регулярки?
        yield log_parts[7], log_parts[-1]

def build_report(log_parser: Generator):
    """Собирает структуру для отчета.
    Конечная структура - список из словарей
    [{"count": 2767, "time_avg": 62.994999999999997,
    "time_max": 9843.5689999999995, "time_sum": 174306.35200000001,
    "url": "/api/v2/internal/html5/phantomjs/queue/?wait=1m", "time_med": 60.073,
    "time_perc": 9.0429999999999993, "count_perc": 0.106}]
    """
    all_req_time = []
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
        all_req_time.append(request_time)

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
            'time_perc': time_sum / sum(all_req_time) * 100
        }
        report_list.append(current_url_data)
    return report_list


def main():
     latest_log = find_latest_logfile("log")
     log = read_log_line(latest_log.path)
     lines = log_parser(log)
     pprint(build_report(lines))

if __name__ == "__main__":
    main()
