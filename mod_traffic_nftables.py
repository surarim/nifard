#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

# Встроенные модули
import time, sys, subprocess
from threading import Thread

# Внешние модули
try:
  import psycopg2
except ModuleNotFoundError as err:
  print(err)
  sys.exit(1)

# Внутренние модули
try:
  from mod_common import *
except ModuleNotFoundError as err:
  print(err)
  sys.exit(1)

# Класс для работы с трафиком в nftables
class traffic_nftables(Thread):
  # Стартовые параметры
  def  __init__(self, threads_list, todolist):
    super().__init__()
    self.daemon = True
    self.threads_list = threads_list
    self.todolist = todolist

  # Поток чтения трафика из nftables и обновления базы
  def run(self):
    # Запись в лог файл
    log_write('Thread traffic_nftables running')
    try:
    # Подключение к базе
      conn_pg = psycopg2.connect(database='nifard', user=get_config('DatabaseUserName'), password=get_config('DatabasePassword') )
    except psycopg2.DatabaseError as error:
      log_write(error)
      sys.exit(1)
    nft_counters_reset = False
    # Цикл чтения nftables по показателю ip трафик
    while not app_work.empty():
      # Проверка что таблица traffic существует
      if subprocess.call('nft list tables | grep traffic',stdout=subprocess.PIPE, shell=True) == 0:
        # Проверка текущего часа, если 00 часов, очищаем счётчики трафика
        if (str(datetime.now()).split(':')[0]).split()[1] == "00" and not nft_counters_reset:
          result = subprocess.check_output('nft reset counters', shell=True).decode()
          nft_counters_reset = True
          log_write('Counters in nftables reseted')
        # Проверка текущего часа, если 01 часа, возвращаем статус очистки обратно
        if (str(datetime.now()).split(':')[0]).split()[1] == "01":
          nft_counters_reset = False
        # Получение данных по трафику для всех ip
        result = subprocess.check_output('nft list counters | head -n -2 | tail +2 | xargs | tr "{" " " | sed "s/} /\\n/g" | cut -d" " -f2,8', shell=True).decode()
        for line in result.splitlines():
          # Выбор ip адреса только соответствующего маске ADUserIPMask
          if line.find(get_config('ADUserIPMask')) != -1:
            if app_work.empty(): break # Повторная проверка на завершение потока
            ip_addr = line.split()[0] # IP адрес
            traffic_nft = line.split()[1] # Трафик из nftables
            # Поиск в базе выбранного ip адреса
            cursor = conn_pg.cursor()
            try:
              cursor.execute("select ip,traffic from users where ip = %s;", (ip_addr,))
            except psycopg2.DatabaseError as error:
              log_write(error)
              sys.exit(1)
            conn_pg.commit()
            rows = cursor.fetchall()
            for row in rows:
              traffic_db = row[1] # Трафик из базы
              break
            # Если ip адрес есть и его трафик изменился, меняем его в базе
            if rows and (int(traffic_db) != int(traffic_nft)):
              try:
                cursor.execute("update users set traffic = %s where ip = %s;", (traffic_nft,ip_addr,))
              except psycopg2.DatabaseError as error:
                log_write(error)
                sys.exit(1)
              conn_pg.commit()
            cursor.close()
      # Ожидание потока
      for tick in range(5):
        if app_work.empty():
          break
        time.sleep(1)
      if app_work.empty(): break # Повторная проверка на завершение потока
    conn_pg.close()
    # Запись в лог файл
    log_write('Thread traffic_nftables stopped')
    # Удаление потока из списка
    self.threads_list.get()
