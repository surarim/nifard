#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import os, psycopg2, threading, time, sys, signal

exit = False # Завершение работы приложения
oif = 'enp5s0' # Имя внешнего интерфейса (Internet)
database_name = "nifard" # Имя базы данных
user_name = "postgres" # Имя пользователя базы
user_password = "" # Пароль пользователя базы
log_file = '/var/log/nifard/nifard-server.log'

# Чтение файла конфигурации
try:
  if os.path.isfile('/etc/nifard/nifard-config'):
    configfile = open('/etc/nifard/nifard-config')
  else:
    configfile = open('nifard-config')
except IOError as error:
  print(error)
else:
  values = []
  for line in configfile:
    param = line.partition('=')[::2]
    if param[0].strip().isalpha() and param[1].strip().find('#') == -1:
      values.append(param[0].strip())
      values.append(param[1].strip())
  print(values)

# Обработчик сигналов завершения процесса
def kill_signals(signum, frame):
  # Очистка правил и логирование
  os.system('nft flush ruleset')
  with open(log_file, 'a') as log:
    log.write('Server Stopped\n')
  global exit
  exit = True
signal.signal(signal.SIGINT, kill_signals)
signal.signal(signal.SIGTERM, kill_signals)

# Поток чтения базы и изменений в nftables
def db_nft():
  # Connection to the database
  # Подключение к базе
  try:
    conn_pg = psycopg2.connect(database=database_name, user=user_name, password=user_password)
  except psycopg2.OperationalError as error:
    print(format(error))
    sys.exit(1)
  # Очистка правил, создание таблицы nat и цепочки postrouting
  os.system('nft flush ruleset')
  os.system('nft add table nat')
  os.system('nft add chain nat postrouting { type nat hook postrouting priority 100 \; }')
  # Цикл чтения таблицы
  while True:
    if exit:
      break
    command = ''
    # Чтение из таблицы базы данных
    cursor = conn_pg.cursor()
    cursor.execute("select * from users;")
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
          command = command + 'nft add rule nat postrouting ip saddr '+ip+' oif '+oif+' masquerade\n'
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
  with open(log_file, 'a') as log:
    log.write('Server Started\n')
  thread_db_nft = threading.Thread(target=db_nft, name="db_nft")
  thread_db_nft.start()
  thread_db_nft.join()
