#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import os, psycopg2, threading, time, sys, signal, subprocess
from pypsrp.client import Client
from scapy.all import *

exit = False # Завершение работы приложения
config = [] # Список параметров файла конфигурации
ip_local = [] # Список ip адресов самого сервера
rules_list = '' # Строка со списком правил для nftables

#------------------------------------------------------------------------------------------------

# Функция записи в лог файл
def log_write(message):
  # Подготовка лог файла
  if not os.path.isfile(config_get('LogFile')):
    logdir = os.path.dirname(config_get('LogFile'))
    if not os.path.exists(logdir):
      os.makedirs(logdir)
    open(config_get('LogFile'),'a').close()
  # Запись в лог файл
  with open(config_get('LogFile'),'a') as logfile:
    logfile.write(str(datetime.now())+' '+message+'\n')

#------------------------------------------------------------------------------------------------

# Функция получения значений параметров конфигурации
def config_get(key):
  global config
  if not config:
    # Чтение файла конфигурации
    try:
      if os.path.isfile('/etc/nifard/nifard-config'):
        configfile = open('/etc/nifard/nifard-config')
      else:
        configfile = open('nifard-config')
    except IOError as error:
      log_write(error)
    else:
      for line in configfile:
        param = line.partition('=')[::2]
        if param[0].strip().isalpha() and param[1].strip().find('#') == -1:
          config.append(param[0].strip())
          config.append(param[1].strip())
  return config[config.index(key)+1]

#------------------------------------------------------------------------------------------------

def ip_local_get():
  global ip_local
  # Получение ip адресов самого сервера
  try:
    ip_local=(subprocess.check_output('hostname -I', shell=True).strip()).decode().split()
  except OSError as error:
    log_write(error)
    sys.exit(1)
  return ip_local

# Функция инициализации настроек и среды сервера
def init_server():
  log_write('Server Started')

#------------------------------------------------------------------------------------------------

# Поток изменений в nftables
def setup_nftables():
  global rules_list
  # Запись в лог файл
  log_write('Thread setup_nftables running')
  try:
    # Подключение к базе
    conn_pg = psycopg2.connect(database='nifard', user=config_get('DatabaseUserName'), password=config_get('DatabasePassword') )
  except psycopg2.DatabaseError as error:
    log_write(error)
    sys.exit(1)
  try:
    # Очистка правил nftables
    subprocess.call('nft flush ruleset', shell=True)
  except OSError as error:
    log_write(error)
    sys.exit(1)
  # Создание таблицы nat и цепочки postrouting в nftables
  subprocess.call('nft add table nat', shell=True)
  subprocess.call('nft add chain nat postrouting { type nat hook postrouting priority 100 \; }', shell=True)
  # Создание таблицы traffic и цепочки prerouting в nftables
  subprocess.call('nft add table traffic', shell=True)
  subprocess.call('nft add chain traffic prerouting {type filter hook prerouting priority 0\;}', shell=True)
  # Цикл чтения таблицы
  while not exit:
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
    for row in rows:
      rule_nat = '' # Обнуление текущего правила для nat
      rule_traffic = '' # Обнуление текущего правила для traffic
      ip = row[0] # IP адрес
      username = row[1] # Имя пользователя
      speed = row[2] # Скорость
      access = row[3] # Тип доступа
      # Проверка ip адреса на валидность
      if ip.count('.') == 3 and ip.find(config_get('ADUserIPMask')) != -1:
        # Проверка типа доступа и скорости
        if access.find('always') != -1 or (access.find('ad') !=-1 and speed != 'no'):
          # Проверка на уже добавленное правило
          if ip not in rules_list:
            # Формирование правила в nat
            rule_nat = 'nft add rule nat postrouting ip saddr '+ip+' oif '+config_get('InternetInterface')+' masquerade\n'
            # Формирование правила в traffic
            rule_traffic = 'nft add rule traffic prerouting ip daddr '+ip+' counter\n'
            # Добавление строки доступа для выбранного ip в строку с другими правилами
            rules_list = rules_list + rule_nat + rule_traffic
            # Добавление текущих правил в nftables
            subprocess.call(rule_nat + rule_traffic, shell=True)
            # Запись в лог файл
            log_write('Added '+ip+' in nftables')
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
  log_write('Thread setup_nftables stopped')

#------------------------------------------------------------------------------------------------
# Поток чтения трафика и обновления базы
def traffic_nftables():
  # Запись в лог файл
  log_write('Thread traffic_nftables running')
  try:
  # Подключение к базе
    conn_pg = psycopg2.connect(database='nifard', user=config_get('DatabaseUserName'), password=config_get('DatabasePassword') )
  except psycopg2.DatabaseError as error:
    log_write(error)
    sys.exit(1)
  # Цикл чтения nftables по показетелю ip трафик
  while not exit:
    if subprocess.call('nft list tables | grep traffic',stdout=subprocess.PIPE, shell=True) == 0:
      result = subprocess.check_output('nft list table traffic | grep "ip daddr" | cut -d" " -f3,8', shell=True).decode()
      for line in result.splitlines():
        # Выбор ip адреса только соответствующего маске ADUserIPMask
        if line.find(config_get('ADUserIPMask')) != -1:
          # Повторная проверка на завершение потока
          if exit:
            break
          # Поиск в базе выбранного ip адреса
          cursor = conn_pg.cursor()
          try:
            cursor.execute("select ip,traffic from users where ip = %s;", (line.split()[0],))
          except psycopg2.DatabaseError as error:
            log_write(error)
            sys.exit(1)
          conn_pg.commit()
          rows = cursor.fetchall()
          # Если ip адрес есть и его трафик изменился, меняем его в базе
          if rows and (int(rows[0][1]) != int(line.split()[1])):
            try:
              cursor.execute("update users set traffic = %s where ip = %s;", (line.split()[1],line.split()[0],))
            except psycopg2.DatabaseError as error:
              log_write(error)
              sys.exit(1)
            conn_pg.commit()
            # Запись в лог файл
            log_write('Update '+line.split()[0]+' traffic:'+line.split()[1])
          cursor.close()
    # Ожидание потока
    for tick in range(5):
      time.sleep(1)
      if exit:
        break
  conn_pg.close()
  # Запись в лог файл
  log_write('Thread traffic_nftables stopped')

#------------------------------------------------------------------------------------------------

# Поток чтения журнала security и получения связки: ip пользователь
# Затем добавление новых записей в базу данных
def track_events():
  # Запись в лог файл
  log_write('Thread track_events running')
  while not exit:
    # Подключение в серверу и получение журнала security со всеми фильтрами
    client = Client(config_get('ADServer'), auth="kerberos", ssl=False, username=config_get('ADUserName'), password=config_get('ADUserPassword'))
    script = """Get-EventLog -LogName security -ComputerName """+config_get('ADServer')+""" -Newest 100 -InstanceId 4624 | Where-Object {($_.ReplacementStrings[5] -notlike '*$*') -and ($_.ReplacementStrings[5] -notlike '*/*') -and ($_.ReplacementStrings[5] -notlike '*АНОНИМ*') -and ($_.ReplacementStrings[18] -notlike '*-*')} | Select-Object @{Name="IpAddress";Expression={ $_.ReplacementStrings[18]}},@{Name="UserName";Expression={ $_.ReplacementStrings[5]}} -Unique"""
    result, streams, had_error = client.execute_ps(script)
    try:
      # Подключение к базе
      conn_pg = psycopg2.connect(database='nifard', user=config_get('DatabaseUserName'), password=config_get('DatabasePassword') )
    except psycopg2.DatabaseError as error:
      log_write(error)
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
        log_write('New '+line.split()[0]+' '+line.split()[1]+' speed:'+speed)
        # Поиск в базе выбранного ip адреса
        cursor = conn_pg.cursor()
        try:
          cursor.execute("select ip,username,speed from users where ip = %s;", (line.split()[0],))
        except psycopg2.DatabaseError as error:
          log_write(error)
          sys.exit(1)
        conn_pg.commit()
        rows = cursor.fetchall()
        # Если ip адреса нет в базе, добавляем
        if not rows:
          try:
            cursor.execute("insert into users values (%s, %s, %s, 'ad', 0);", (line.split()[0],line.split()[1],speed,))
          except psycopg2.DatabaseError as error:
            log_write(error)
            sys.exit(1)
          # Запись в лог файл
          log_write('Insert '+line.split()[0]+' '+line.split()[1]+' speed:'+speed)
          conn_pg.commit()
        # Если ip адрес есть, но отличается имя пользователя или скорость, меняем в базе
        if rows and (str(rows[0][1]) != str(line.split()[1]) or str(rows[0][2]) != speed):
          try:
            cursor.execute("update users set username = %s, speed = %s where ip = %s;", (line.split()[1],speed,line.split()[0],))
          except psycopg2.DatabaseError as error:
            log_write(error)
            sys.exit(1)
          # Запись в лог файл
          log_write('Update '+line.split()[0]+' '+line.split()[1]+' speed:'+speed)
          conn_pg.commit()
        cursor.close()
    conn_pg.close()
    # Ожидание потока
    for tick in range(5):
      time.sleep(1)
      if exit:
        break
  # Запись в лог файл
  log_write('Thread track_events stopped')

#------------------------------------------------------------------------------------------------

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
        #print(packet[1].summary())
        pass
  # Главный модуль выполнения класса
  def run(self):
    self.socket = conf.L2listen(type=ETH_P_ALL, filter="ip")
    sniff(opened_socket=self.socket, iface=config_get('LANInterface'), prn=self.work_with_packet)

#------------------------------------------------------------------------------------------------

# Запуск всех компонентов сервера
if __name__ =='__main__':
  # Начальная инициализация
  init_server()
  # Запуск потока обработки сетевых пакетов
  sniffer = sniff_packets()
  sniffer.start()
  # Запуск потока изменений в nftables
  thread_setup_nftables = threading.Thread(target=setup_nftables)
  thread_setup_nftables.start()
  # Запуск потока чтения трафика из nftables
  thread_traffic_nftables = threading.Thread(target=traffic_nftables)
  thread_traffic_nftables.start()
  # Запуск потока чтения данных из AD
  thread_track_events = threading.Thread(target=track_events)
  thread_track_events.start()
  try:
    # Цикл работы потока сетевых пакетов
    while True:
      time.sleep(0.1)
  except KeyboardInterrupt:
    exit = True
