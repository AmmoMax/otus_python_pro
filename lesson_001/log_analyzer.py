#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import datetime
import re
from collections import namedtuple
from pathlib import Path

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
            ActualLogFile.path = file.name
            ActualLogFile.delta = delta.days
            ActualLogFile.date = match
            res_log_files.append(ActualLogFile)
    latest = min(res_log_files, key=lambda x: x.delta)
    return latest





def main():
    find_latest_logfile("log")

if __name__ == "__main__":
    main()
