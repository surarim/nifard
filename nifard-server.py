#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import os, psycopg2, threading, time, sys, signal, subprocess
from pypsrp.client import Client
from scapy.all import *

exit = False # Завершение работы приложения
config = [] # Список параметров файла конфигурации
ip_traf = [] # Список кэшированных ip адресов и их трафик
ip_local = [] # Список ip адресов самого сервера

# Получение значения параметра конфигурации
def config_get(key):
  return config[config.index(key)+1]

# Получение ip адресов самого сервера
try:
  ip_local=(subprocess.check_output('hostname -I', shell=True).strip()).decode().split()
except OSError as error:
  print(error)
  sys.exit(1)

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
if not os.path.isfile(config_get('LogFile')):
  logdir = os.path.dirname(config_get('LogFile'))
  if not os.path.exists(logdir):
    os.makedirs(logdir)
  open(config_get('LogFile'),'a').close()

# Поток изменений в nftables
def setup_nftables():
  # Запись в лог файл
  with open(config_get('LogFile'),'a') as logfile:
    logfile.write('Thread setup_nftables running\n')
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
  while not exit:
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
        # Проверка типа доступа и скорости
        if access.find('always') != -1 or (access.find('ad') !=-1 and speed != 'no'):
          # Создание строки доступа для выбранного ip
          command = command + 'nft add rule nat postrouting ip saddr '+ip+' oif '+config_get('InternetInterface')+' masquerade\n'
    # Очистка таблицы nat и добавление всех правил
    subprocess.call('nft flush table nat', shell=True)
    subprocess.call(command, shell=True)
    # Закрытие курсора и задержка выполнения
    cursor.close()
    # Ожидание потока
    for tick in range(5):
      time.sleep(1)
      if exit:
        break
  conn_pg.close()
  subprocess.call('nft flush ruleset', shell=True)
  # Запись в лог файл
  with open(config_get('LogFile'),'a') as logfile:
    logfile.write('Thread setup_nftables stopped\n')

# Поток чтения журнала security и получения связки: ip пользователь
# Затем добавление новых записей в базу данных
def track_events():
  # Запись в лог файл
  with open(config_get('LogFile'),'a') as logfile:
    logfile.write('Thread track_events running\n')
  while not exit:
    # Подключение в серверу и получение журнала security со всеми фильтрами
    client = Client(config_get('ADServer'), auth="kerberos", ssl=False, username=config_get('ADUserName'), password=config_get('ADUserPassword'))
    script = """Get-EventLog -LogName security -ComputerName """+config_get('ADServer')+""" -Newest 100 -InstanceId 4624 | Where-Object {($_.ReplacementStrings[5] -notlike '*$*') -and ($_.ReplacementStrings[5] -notlike '*/*') -and ($_.ReplacementStrings[5] -notlike '*АНОНИМ*') -and ($_.ReplacementStrings[18] -notlike '*-*')} | Select-Object @{Name="IpAddress";Expression={ $_.ReplacementStrings[18]}},@{Name="UserName";Expression={ $_.ReplacementStrings[5]}} -Unique"""
    result, streams, had_error = client.execute_ps(script)
    try:
      # Connection to the database
      # Подключение к базе
      conn_pg = psycopg2.connect(database='nifard', user=config_get('DatabaseUserName'), password=config_get('DatabasePassword') )
    except psycopg2.DatabaseError as error:
      print(error)
      sys.exit(1)
    for line in result.splitlines():
      # Выбор ip адреса только соответствующего маске ADUserIPMask
      if line.find(config_get('ADUserIPMask')) != -1:
        # Повторная проверка на завершение потока
        if exit:
          break
        # Получение группы для текущего пользователя (фильтрация по internet)
        script = """([ADSISEARCHER]'samaccountname="""+line.split()[1]+"""').Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1' -like 'internet_*'"""
        speed, streams, had_error = client.execute_ps(script)
        # Проверка на пустоту и отсутствие группы скорости
        if not speed or speed.find('internet_') == -1:
          speed = 'no'
        # Запись в лог файл
        with open(config_get('LogFile'),'a') as logfile:
          logfile.write('New ip:'+line.split()[0]+'  user:'+line.split()[1]+'  speed:'+speed+'\n')
        # Поиск в базе выбранного ip адреса
        cursor = conn_pg.cursor()
        try:
          cursor.execute("select ip,username,speed from users where ip = %s;", (line.split()[0],))
        except psycopg2.DatabaseError as error:
          print(error)
          sys.exit(1)
        conn_pg.commit()
        rows = cursor.fetchall()
        # Если ip адреса нет в базе, добавляем
        if not rows:
          try:
            cursor.execute("insert into users values (%s, %s, %s, 'ad');", (line.split()[0],line.split()[1],speed,))
          except psycopg2.DatabaseError as error:
            print(error)
            sys.exit(1)
          # Запись в лог файл
          with open(config_get('LogFile'),'a') as logfile:
            logfile.write('Insert ip:'+line.split()[0]+'  user:'+line.split()[1]+'  speed:'+speed+'\n')
          conn_pg.commit()
        # Если ip адрес есть, но отличается имя пользователя или скорость, меняем в базе
        if rows and (rows[0][1] != line.split()[1] or rows[0][2] != speed):
          try:
            cursor.execute("update users set username = %s, speed = %s where ip = %s;", (line.split()[1],speed,line.split()[0],))
          except psycopg2.DatabaseError as error:
            print(error)
            sys.exit(1)
          # Запись в лог файл
          with open(config_get('LogFile'),'a') as logfile:
            logfile.write('Update ip:'+line.split()[0]+'  user:'+line.split()[1]+'  speed:'+speed+'\n')
          conn_pg.commit()
        cursor.close()
    conn_pg.close()
    # Ожидание потока
    for tick in range(5):
      time.sleep(1)
      if exit:
        break
  # Запись в лог файл
  with open(config_get('LogFile'),'a') as logfile:
    logfile.write('Thread track_events stopped\n')

# Класс для работы с сетевыми пакетами
class sniff_packets(Thread):
  # Стартовые параметры
  def  __init__(self):
    super().__init__()
    self.socket = None
    self.daemon = True
  # Обработчик каждого пакета
  def work_with_packet(self, packet):
    # Проверка пакета на валидность и не широковещательность
    if IP in packet[0] and packet[1].dst.find('255')==-1:
      # Проверка адреса назначения на локальные адреса, что это не сервер и исходящий адрес из Интернета
      if packet[1].dst.find(config_get('ADUserIPMask'))!=-1 and packet[1].dst not in ip_local and packet[1].src.find(config_get('ADUserIPMask'))==-1:
        # Добавление нового счётчика трафика
        if packet[1].dst not in ip_traf:
          ip_traf.append(packet[1].dst)
          ip_traf.append(packet[1].len)
        # Добавление показаний трафика к уже существующему счётчику
        else:
          pos = ip_traf.index(packet[1].dst)
          ip_traf[pos+1]=ip_traf[pos+1]+packet[1].len

  # Главный модуль выполнения класса
  def run(self):
    self.socket = conf.L2listen(type=ETH_P_ALL, filter="ip")
    sniff(opened_socket=self.socket, iface=config_get('LANInterface'), prn=self.work_with_packet)

# Запуск всех компонентов сервера
if __name__ =='__main__':
  # Запуск потока обработки сетевых пакетов
  sniffer = sniff_packets()
  sniffer.start()
  # Запуск потока изменений в nftables
  thread_setup_nftables = threading.Thread(target=setup_nftables, name="setup_nftables")
  thread_setup_nftables.start()
  # Запуск потока чтения данных из AD
  thread_track_events = threading.Thread(target=track_events, name="track_events")
  thread_track_events.start()
  try:
    # Цикл работы потока сетевых пакетов
    while True:
      time.sleep(0.1)
      print(ip_traf)
  except KeyboardInterrupt:
    exit = True
