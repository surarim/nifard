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

# Класс для работы с изменениями в nftables
class setup_nftables(Thread):
  # Стартовые параметры
  def  __init__(self, threads_list, todolist):
    super().__init__()
    self.daemon = True
    self.threads_list = threads_list
    self.todolist = todolist

  # Поток изменений в nftables
  def run(self):
    # Запись в лог файл
    log_write('Thread setup_nftables running')
    try:
      # Подключение к базе
      conn_pg = psycopg2.connect(database='nifard', user=get_config('DatabaseUserName'), password=get_config('DatabasePassword'))
    except psycopg2.DatabaseError as error:
      log_write(error)
      sys.exit(1)
    # Цикл чтения таблицы
    while not app_work.empty():
      # Чтение из таблицы базы данных
      cursor = conn_pg.cursor()
      try:
        cursor.execute("select * from users;")
      except psycopg2.DatabaseError as error:
        log_write(error)
        subprocess.call('nft flush ruleset', shell=True)
        sys.exit(1)
      conn_pg.commit()
      rows = cursor.fetchall()
      # Получение текущего списка правил nftables по таблице nat
      rules_nat = subprocess.check_output('nft list table nat -a | head -n -2 | tail +4', shell=True).decode().strip()
      try:
        # Получение текущего списка правил nftables по таблице traffic
        rules_traffic = subprocess.check_output('nft list table traffic -a | grep daddr', shell=True).decode().strip()
      except:
        rules_traffic = ''
      # Получение текущего списка правил nftables по таблице speed
      rules_speed = subprocess.check_output('nft list table speed -a | head -n -2 | tail +4', shell=True).decode().strip()
      #
      for row in rows:
        if app_work.empty(): break # Повторная проверка на завершение потока
        ip_addr = row[0] # IP адрес
        username = row[1] # Имя пользователя
        computer = row[2] # Имя компьютера
        domain = row[3] # Имя домена
        speed = row[4] # Группа скорости
        access = row[5] # Тип доступа
        # Проверка ip адреса на валидность
        if ip_addr.count('.') == 3 and ip_addr.find(get_config('ADUserIPMask')) != -1:
          # Обнуление переменных модификаций правил
          speed_db = 0
          speed_nft = 0
          # Определение модификаций
          try:
            # Если лимит
            if int(speed[speed.find('_')+1:])//1024 >= 1:
              speed_db = int(speed[speed.find('_')+1:])//1024
            else:
              speed_db = int(speed[speed.find('_')+1:])
          except:
            # Если безлимит
            speed_db = speed[speed.find('_')+1:]
          # Получение скорости из nftables
          if ' '+ip_addr+' ' in rules_speed:
            # Получение скорости из nftables
            for line in rules_speed.splitlines():
              if line.split()[2] == ip_addr:
                speed_nft = int(line.split()[6])
                break
          else:
            if ' '+ip_addr+' ' in rules_traffic:
              speed_nft = 'nolimit'
            else:
              speed_nft = 'disable'
          #
          # Удаление правил в том числе для пересоздания
          if speed == 'disable' or speed_db != speed_nft:
            # Проверка на наличие его в rules_nat
            if ' '+ip_addr+' ' in rules_nat:
              rule_nat = ''
              # Получение номера правила для таблицы nat
              for line in rules_nat.splitlines():
                if line.split()[2] == ip_addr:
                  rule_nat = line.split()[8]
                  rule_nat = 'nft delete rule nat postrouting handle '+rule_nat+'\n'
                  break
              # Получение номера правила и удаление для таблицы traffic
              rule_traffic = ''
              rule_counter = 'nft delete counter traffic '+ip_addr+'\n'
              # Получение номера правила и удаление для таблицы traffic
              for line in rules_traffic.splitlines():
                if line.split()[2] == ip_addr:
                  rule_traffic = line.split()[10]
                  rule_traffic = 'nft delete rule traffic prerouting handle '+rule_traffic+'\n'
                  break
              rule_speed = ''
              # Получение номера правила и удаление для таблицы speed
              for line in rules_speed.splitlines():
                if line.split()[2] == ip_addr:
                  rule_speed = line.split()[11]
                  rule_speed = 'nft delete rule speed prerouting handle '+rule_speed+'\n'
                  break
              # Удаление выбранного правила из nftables
              subprocess.call(rule_traffic + rule_nat + rule_speed, shell=True)
              # Ожидание перед удалением счётчика
              time.sleep(1)
              subprocess.call(rule_counter, shell=True)
              # Запись в лог файл
              log_write('Delete '+ip_addr+' from nftables')
          #
          # Добавление правил
          if access.find('always') != -1 or (access != 'no' and speed != 'disable' and speed.find('disable') == -1):
            # Если ip адреса ещё нет в nftables, и при этом он не принадлежит другому домену, то добавляем
            if ' '+ip_addr+' ' not in rules_nat and (domain == get_config('DomainRealm') or domain == 'Domain Unknown'):
              # Формирование правила в nat
              rule_nat = 'nft add rule nat postrouting ip saddr '+ip_addr+' oif '+get_config('InternetInterface')+' masquerade\n'
              # Формирование правила в traffic (подсчёт трафика)
              rule_traffic = 'nft add counter traffic '+ip_addr+'\n'
              rule_traffic += 'nft add rule traffic prerouting ip daddr '+ip_addr+' iif '+get_config('InternetInterface')+' counter name '+ip_addr+'\n'
              # Формирование правила в speed (оганичение трафика)
              rule_limit = ''
              if speed.find('nolimit') == -1:
                rule_limit = 'nft add rule speed prerouting ip daddr '+ip_addr+' limit rate over '+speed[speed.find('_')+1:]+' kbytes/second drop\n'
              # Добавление текущих правил в nftables
              subprocess.call(rule_nat + rule_traffic + rule_limit, shell=True)
              # Запись в лог файл
              log_write('Adding '+ip_addr+' in nftables')
          #
      # Закрытие курсора и задержка выполнения
      cursor.close()
      # Ожидание потока
      for tick in range(5):
        if app_work.empty():
          break
        time.sleep(1)
    conn_pg.close()
    subprocess.call('nft flush ruleset', shell=True)
    # Запись в лог файл
    log_write('Thread setup_nftables stopped')
    # Удаление потока из списка
    self.threads_list.get()
