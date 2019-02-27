#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import os, psycopg2, threading, time, sys, signal, subprocess
from pypsrp.client import Client

exit = False # Завершение работы приложения
config = [] # Список параметров файла конфигурации

# Получение значения параметра конфигурации
def config_get(key):
  return config[config.index(key)+1]

# Чтение файла конфигурации
try:
  if os.path.isfile('/etc/nifard/nifard-config'):
    configfile = open('/etc/nifard/nifard-config')
  else:
    configfile = open('nifard-config')
except IOError as error:
  print(error)
else:
  for line in configfile:
    param = line.partition('=')[::2]
    if param[0].strip().isalpha() and param[1].strip().find('#') == -1:
      config.append(param[0].strip())
      config.append(param[1].strip())

# Подготовка лог файла
if os.path.isfile(config_get('LogFile')):
  logfile = open(config_get('LogFile'),'a')
else:
  logdir = os.path.dirname(config_get('LogFile'))
  if not os.path.exists(logdir):
    os.makedirs(logdir)
  logfile = open(config_get('LogFile'),'a')

# Обработчик сигналов завершения процесса
def kill_signals(signum, frame):
  # Очистка правил и логирование
  subprocess.call('nft flush ruleset', shell=True)
  logfile.write('Server Stopped\n')
  global exit
  exit = True
signal.signal(signal.SIGINT, kill_signals)
signal.signal(signal.SIGTERM, kill_signals)

# Поток чтения базы и изменений в nftables
def db_nft():
  # Connection to the database
  # Подключение к базе
  try:
    conn_pg = psycopg2.connect(database='nifard', user=config_get('DatabaseUserName'), password=config_get('DatabasePassword') )
  except psycopg2.DatabaseError as error:
    print(error)
    sys.exit(1)
  # Очистка правил, создание таблицы nat и цепочки postrouting
  try:
    subprocess.call('nft flush ruleset', shell=True)
  except OSError as error:
    print(error)
    sys.exit(1)
  subprocess.call('nft add table nat', shell=True)
  subprocess.call('nft add chain nat postrouting { type nat hook postrouting priority 100 \; }', shell=True)
  # Цикл чтения таблицы
  while True:
    if exit:
      break
    command = ''
    # Чтение из таблицы базы данных
    cursor = conn_pg.cursor()
    try:
      cursor.execute("select * from users;")
    except psycopg2.DatabaseError as error:
      print(error)
      subprocess.call('nft flush ruleset', shell=True)
      sys.exit(1)
    conn_pg.commit()
    rows = cursor.fetchall()
    for row in rows:
      ip = row[0] # IP адрес
      username = row[1] # Имя пользователя
      speed = row[2] # Скорость
      access = row[3] # Тип доступа
      # Проверка ip адреса на валидность
      if ip.count('.') == 3 and ip.find(config_get('ADUserIPMask')) != -1:
        # Проверка типа доступа
        if access.find('always') != -1 or access.find('ad') !=-1:
          # Создание строки доступа для выбранного ip
          command = command + 'nft add rule nat postrouting ip saddr '+ip+' oif '+config_get('InternetInterface')+' masquerade\n'
    # Очистка таблицы nat и добавление всех правил
    subprocess.call('nft flush table nat', shell=True)
    subprocess.call(command, shell=True)
    # Закрытие курсора и задержка выполнения
    cursor.close()
    time.sleep(5)
  conn_pg.close()

# Поток чтения журнала security и получения связки: ip пользователь
# Затем добавление новых записей в базу данных
def track_events():
  while True:
    if exit:
      break
    # Подключение в серверу и получение журнала security со всеми фильтрами
    client = Client(config_get('ADServer'), auth="kerberos", ssl=False, username=config_get('ADUserName'), password=config_get('ADUserPassword'))
    script = """Get-EventLog -LogName security -ComputerName """+config_get('ADServer')+""" -Newest 100 -InstanceId 4624 | Where-Object {($_.ReplacementStrings[5] -notlike '*$*') -and ($_.ReplacementStrings[5] -notlike '*/*') -and ($_.ReplacementStrings[5] -notlike '*АНОНИМ*') -and ($_.ReplacementStrings[18] -notlike '*-*')} | Select-Object @{Name="IpAddress";Expression={ $_.ReplacementStrings[18]}},@{Name="UserName";Expression={ $_.ReplacementStrings[5]}} -Unique"""
    result, streams, had_error = client.execute_ps(script)
    # Connection to the database
    # Подключение к базе
    try:
      conn_pg = psycopg2.connect(database='nifard', user=config_get('DatabaseUserName'), password=config_get('DatabasePassword') )
    except psycopg2.DatabaseError as error:
      print(error)
      sys.exit(1)
    # Выбор результата только соответствующего маске
    for line in result.splitlines():
      if line.find(config_get('ADUserIPMask')) != -1:
        print('New ip:'+line.split()[0]+"  user:"+line.split()[1])
        # Чтение из таблицы базы данных
        cursor = conn_pg.cursor()
        try:
          cursor.execute("select ip,username from users where ip = %s;", (line.split()[0],))
        except psycopg2.DatabaseError as error:
          print(error)
          sys.exit(1)
        conn_pg.commit()
        rows = cursor.fetchall()
        # Если ip нет в базе, добавляем
        if not rows:
          try:
            cursor.execute("insert into users values (%s, %s, 'internet_128', 'ad');", (line.split()[0],line.split()[1],))
          except psycopg2.DatabaseError as error:
            print(error)
            sys.exit(1)
          print('Insert ip:'+line.split()[0]+"  user:"+line.split()[1])
          conn_pg.commit()
        # Если ip адрес есть, но отличается имя пользователя, меняем в базе
        if rows and rows[0][1] != line.split()[1]:
          try:
            cursor.execute("update users set username = %s where ip = %s;", (line.split()[1],line.split()[0],))
          except psycopg2.DatabaseError as error:
            print(error)
            sys.exit(1)
          print('Update ip:'+line.split()[0]+"  user:"+line.split()[1])
          conn_pg.commit()
        cursor.close()
    # Задержка выполнения
    conn_pg.close()
    time.sleep(5)

# Running threads
# Запуск потоков
if __name__ =='__main__':
  logfile.write('Server Started\n')
  thread_db_nft = threading.Thread(target=db_nft, name="db_nft")
  thread_track_events = threading.Thread(target=track_events, name="track_events")
  thread_db_nft.start()
  thread_track_events.start()
  thread_db_nft.join()
  thread_track_events.join()
