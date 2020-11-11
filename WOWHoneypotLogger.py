from logging import getLogger, StreamHandler, Formatter, FileHandler, INFO
import sys


class WOWHoneypotLogger:

  def __init__(self, access_log_file: str = None):
    # HTTPリクエストをロギングするためのロガー
    access_logger = getLogger("access_logger")
    access_logger.setLevel(INFO)
    access_sysout_handler = StreamHandler(sys.stdout)
    # Jsonで受ける予定なのでフォーマットは固定
    access_sysout_handler.setFormatter(Formatter("%(message)s"))
    access_logger.addHandler(access_sysout_handler)
    if access_log_file is not None:
      access_file_handler = FileHandler(filename=access_log_file)
      access_logger.addHandler(access_file_handler)
    self.__access_logger = access_logger

    # システム情報のロギングをするためのロガー
    # コンソール出力するだけ
    system_logger = getLogger("system_logger")
    system_logger.setLevel(INFO)
    system_sysout_handler = StreamHandler(sys.stdout)
    system_logger.addHandler(system_sysout_handler)
    self.__system_logger = system_logger

  def access(self, message: str):
    self.__access_logger.info(message)

  def system(self, message: str):
    self.__system_logger.info(message)
