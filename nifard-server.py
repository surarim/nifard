#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import os, psycopg2, threading, time, sys, signal, subprocess

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
  os.system('nft flush ruleset')
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
    subprocess.call('nft flush ruleset')
  except OSError as error:
    print(error)
    sys.exit(1)
  subprocess.call('nft add table nat')
  subprocess.call('nft add chain nat postrouting { type nat hook postrouting priority 100 \; }')
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
      sys.exit(1)
    conn_pg.commit()
    rows = cursor.fetchall()
    for row in rows:
      ip = row[0] # IP адрес
      username = row[1] # Имя пользователя
      speed = row[2] # Скорость
      access = row[3] # Тип доступа
      # Проверка ip адреса на валидность
      if ip.count('.') == 3 and ip.find('192.168.') != -1:
        # Проверка типа доступа
        if access.find('always') != -1 or access.find('ad') !=-1:
          # Создание строки доступа для выбранного ip
          command = command + 'nft add rule nat postrouting ip saddr '+ip+' oif '+config_get('InternetInterface')+' masquerade\n'
    # Очистка таблицы nat и добавление всех правил
    os.system('nft flush table nat')
    os.system(command)
    # Закрытие курсора и задержка выполнения
    cursor.close()
    time.sleep(1)
  conn_pg.close()

# Running threads
# Запуск потоков
if __name__ =='__main__':
  logfile.write('Server Started\n')
  thread_db_nft = threading.Thread(target=db_nft, name="db_nft")
  thread_db_nft.start()
  thread_db_nft.join()
