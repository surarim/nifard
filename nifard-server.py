#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import os, time, threading, sys, subprocess, socket, signal
from multiprocessing import Queue
try:
  import psycopg2
  from pypsrp.client import Client
  from scapy.all import *
except ModuleNotFoundError as err:
  print(err)
  sys.exit(1)

config = [] # Список параметров файла конфигурации

#------------------------------------------------------------------------------------------------

# Обработчик сигнала завершения приложения
def signal_hundler(signal, frame):
  # Инициализация завершения приложения
  app_work.get()

#------------------------------------------------------------------------------------------------

# Функция записи в лог файл
def log_write(message):
  # Подготовка лог файла
  if not os.path.isfile(get_config('LogFile')):
    logdir = os.path.dirname(get_config('LogFile'))
    if not os.path.exists(logdir):
      os.makedirs(logdir)
    open(get_config('LogFile'),'a').close()
  # Запись в лог файл
  with open(get_config('LogFile'),'a') as logfile:
    logfile.write(str(datetime.now()).split('.')[0]+' '+message+'\n')

#------------------------------------------------------------------------------------------------

# Функция получения значений параметров конфигурации
def get_config(key):
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

# Получение ip адресов самого сервера
def get_ip_local():
  try:
    ip_local=(subprocess.check_output('hostname -I', shell=True).strip()).decode().split()
  except OSError as error:
    log_write(error)
    sys.exit(1)
  return ip_local

#------------------------------------------------------------------------------------------------

# Функция инициализации настроек и среды сервера
def init_server():
  if subprocess.call('which nft',stdout=subprocess.PIPE, shell=True) == 1:
    print('nftables not found')
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
  # Создание таблицы speed и цепочки prerouting в nftables
  subprocess.call('nft add table speed', shell=True)
  subprocess.call('nft add chain speed prerouting {type filter hook prerouting priority 0\;}', shell=True)
  log_write('Init Server')

#------------------------------------------------------------------------------------------------

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
    # Добавление в очередь потока
    self.threads_list.put('thread')
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
      # Получение текущего списка правил nftables
      rules_list = subprocess.check_output('nft list table nat', shell=True).decode().strip()
      for row in rows:
        # Повторная проверка на завершение потока
        if app_work.empty():
          break
        rule_nat = '' # Обнуление текущего правила для nat
        rule_traffic = '' # Обнуление текущего правила для traffic
        ip_addr = row[0] # IP адрес
        username = row[1] # Имя пользователя
        computer = row[2] # Имя компьютера
        speed = row[3] # Группа скорости
        access = row[4] # Тип доступа
        # Проверка ip адреса на валидность
        if ip_addr.count('.') == 3 and ip_addr.find(get_config('ADUserIPMask')) != -1:
          # Проверка типа доступа и скорости
          if access.find('always') != -1 or (access.find('ad') !=-1 and speed != 'no'):
            # Проверка на уже добавленное правило
            if ' '+ip_addr+' ' not in rules_list:
              # Формирование правила в nat
              rule_nat = 'nft add rule nat postrouting ip saddr '+ip_addr+' oif '+get_config('InternetInterface')+' masquerade\n'
              # Формирование правила в traffic (подсчёт трафика)
              rule_traffic = 'nft add rule traffic prerouting ip daddr '+ip_addr+' counter\n'
              # Формирование правила в speed (оганичение трафика)
              rule_limit = ''
              if speed.find('nolimit') == -1:
                rule_limit = 'nft add rule speed prerouting ip daddr '+ip_addr+' limit rate over '+speed[speed.find('_')+1:]+' kbytes/second drop\n'
              # Добавление текущих правил в nftables
              subprocess.call(rule_nat + rule_traffic + rule_limit, shell=True)
              # Запись в лог файл
              log_write('Adding '+ip_addr+' in nftables')
          # Проверка на удаление правила
          else:
            # Проверка на наличие его в rules_list
            if ' '+ip_addr+' ' in rules_list:
              # Получение номера правила и удаление для таблицы nat
              rule_nat = subprocess.check_output('nft list table nat -a | grep " '+ip_addr+' " | cut -d" " -f9', shell=True).decode().strip()
              rule_nat = 'nft delete rule nat postrouting handle '+rule_nat+'\n'
              # Получение номера правила и удаление для таблицы traffic
              rule_traffic = subprocess.check_output('nft list table traffic -a | grep '+ip_addr+' | cut -d" " -f11', shell=True).decode().strip()
              rule_traffic = 'nft delete rule traffic prerouting handle '+rule_traffic+'\n'
              # Получение номера правила и удаление для таблицы speed
              rule_speed = subprocess.check_output('nft list table speed -a | grep '+ip_addr+' | cut -d" " -f12', shell=True).decode().strip()
              if rule_speed.isdigit():
                rule_speed = 'nft delete rule speed prerouting handle '+rule_speed+'\n'
              else:
                rule_speed = ''
              # Удаление выбранного правила из nftables
              subprocess.call(rule_nat + rule_traffic + rule_speed, shell=True)
              # Запись в лог файл
              log_write('Delete '+ip_addr+' from nftables')
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

#------------------------------------------------------------------------------------------------

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
    # Добавление в очередь потока
    self.threads_list.put('thread')
    # Запись в лог файл
    log_write('Thread traffic_nftables running')
    try:
    # Подключение к базе
      conn_pg = psycopg2.connect(database='nifard', user=get_config('DatabaseUserName'), password=get_config('DatabasePassword') )
    except psycopg2.DatabaseError as error:
      log_write(error)
      sys.exit(1)
    # Цикл чтения nftables по показателю ip трафик
    while not app_work.empty():
      if subprocess.call('nft list tables | grep traffic',stdout=subprocess.PIPE, shell=True) == 0:
        result = subprocess.check_output('nft list table traffic | grep "ip daddr" | cut -d" " -f3,8', shell=True).decode()
        for line in result.splitlines():
          # Выбор ip адреса только соответствующего маске ADUserIPMask
          if line.find(get_config('ADUserIPMask')) != -1:
            # Повторная проверка на завершение потока
            if app_work.empty():
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
        if app_work.empty():
          break
        time.sleep(1)
    conn_pg.close()
    # Запись в лог файл
    log_write('Thread traffic_nftables stopped')
    # Удаление потока из списка
    self.threads_list.get()

#------------------------------------------------------------------------------------------------

# Класс для работы с AD
class track_events(Thread):
  # Стартовые параметры
  def  __init__(self, threads_list, todolist):
    super().__init__()
    self.daemon = True
    self.threads_list = threads_list
    self.todolist = todolist
    self.ip_clients = [] # Список ip адресов клиентов
    self.ip_terminals = [] # Список ip адресов серверов терминалов

  # Поток чтения журнала security и сетевых пакетов, для получения связки: ip, пользователь, имя пк
  # Затем добавление новых записей в базу данных
  def run(self):
    # Добавление в очередь потока
    self.threads_list.put('thread')
    # Запись в лог файл
    log_write('Thread track_events running')
    # Подключение в серверу
    client = Client(get_config('ADServer'), auth="kerberos", ssl=False, username=get_config('ADUserName'), password=get_config('ADUserPassword'))
    try:
      # Подключение к базе
      conn_pg = psycopg2.connect(database='nifard', user=get_config('DatabaseUserName'), password=get_config('DatabasePassword') )
    except psycopg2.DatabaseError as error:
      log_write(error)
      sys.exit(1)
    while not app_work.empty():
      # Очистка списка новых клиентов
      self.ip_clients.clear()
      #
      # Получение журнала security со всеми фильтрами
      script = """Get-EventLog -LogName security -ComputerName """+get_config('ADServer')+""" -Newest 100 -InstanceId 4624 | Where-Object {($_.ReplacementStrings[5] -notlike '*$*') -and ($_.ReplacementStrings[5] -notlike '*/*') -and ($_.ReplacementStrings[5] -notlike '*АНОНИМ*') -and ($_.ReplacementStrings[18] -notlike '*-*')} | Select-Object @{Name="IpAddress";Expression={ $_.ReplacementStrings[18]}},@{Name="UserName";Expression={ $_.ReplacementStrings[5]}} -Unique"""
      result, streams, had_error = client.execute_ps(script)
      # Цикл добавления клиентов, полученных из журнала, в список
      for line in result.splitlines():
        if line.find(get_config('ADUserIPMask')) != -1 and line not in self.ip_clients:
          # Получение параметров клиента
          ip_addr = line.split()[0] # IP адрес клиента
          username = line.split()[1] # Имя пользователя
          try:
            computer = socket.gethostbyaddr(ip_addr)[0] # Имя компьютера
            computer = computer[0:computer.find('.')] # Имя компьютера без доменной части
          except OSError:
            computer = '*' # Не получено имя компьютера
            pass
          if computer == '':
            computer = '*'
          # Добавление нового клиента в список
          self.ip_clients.append(ip_addr)
          self.ip_clients.append(username)
          self.ip_clients.append(computer)
      #
      # Повторная проверка на завершение потока
      if app_work.empty():
        break
      # Цикл добавления клиентов, полученных из очереди, в список
      while not self.todolist.empty():
        ip_addr = self.todolist.get() # IP адрес клиента
        # Проверка что ip адрес пустой или что он уже есть в списке
        if ip_addr is None or ip_addr in self.ip_clients:
          break
        username = '*' # Имя пользователя неизвестно
        try:
          computer = socket.gethostbyaddr(ip_addr)[0] # Имя компьютера
          computer = computer[0:computer.find('.')] # Имя компьютера без доменной части
        except OSError:
          computer = '*'
          pass
        if computer == '':
          computer = '*'
        # Добавление нового клиента в список
        self.ip_clients.append(ip_addr)
        self.ip_clients.append(username)
        self.ip_clients.append(computer)
      #
      # Цикл добавления новых клиентов в базу
      for pos in range(0,len(self.ip_clients),3):
        # Повторная проверка на завершение потока
        if app_work.empty():
          break
        ip_addr = self.ip_clients[pos] # IP адрес клиента
        username = self.ip_clients[pos+1] # Имя пользователя
        computer = self.ip_clients[pos+2]  # Имя компьютера
        # Проверка операционной системы компьютера
        script = """([ADSISEARCHER]'cn="""+computer+"""').Findone().Properties.operatingsystem"""
        osversion, streams, had_error = client.execute_ps(script)
        # Если серверная операционная система, убираем доступ по пользователю
        if osversion.lower().find('server') != -1:
          username = '*'
        if username != '*':
          # Получение группы для текущего пользователя (фильтрация по internet)
          script = """([ADSISEARCHER]'samaccountname="""+username+"""').Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1' -like 'internet_*'"""
        else:
          # Получение группы для текущего компьютера (фильтрация по internet)
          script = """([ADSISEARCHER]'cn="""+computer+"""').Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1' -like 'internet_*'"""
          username = '*'
        speed, streams, had_error = client.execute_ps(script)
        # Проверка на пустоту и отсутствие группы скорости
        if not speed or speed.find('internet_') == -1:
          speed = 'no'
        # Запись в лог файл
        log_write('Newest '+ip_addr+' '+username+' '+computer+' '+speed)
        #
        # Поиск в базе выбранного ip адреса
        cursor = conn_pg.cursor()
        try:
          cursor.execute("select ip,username,computer,speed,access from users where ip = %s;", (ip_addr,))
        except psycopg2.DatabaseError as error:
          log_write(error)
          sys.exit(1)
        rows = cursor.fetchall()
        #
        # Если ip адреса нет в базе, добавляем
        if not rows:
          try:
            cursor.execute("insert into users values (%s, %s, %s, %s, 'ad', 0);", (ip_addr, username, computer, speed,))
          except psycopg2.DatabaseError as error:
            log_write(error)
            sys.exit(1)
          # Запись в лог файл
          log_write('Insert '+ip_addr+' '+username+' '+computer+' '+speed)
          conn_pg.commit()
        #
        # Если ip адрес есть, и тип доступа не 'no'
        if rows and str(rows[0][4]) != 'no':
          # Если изменилось имя пользователя, имя компьютера или группа скорости
          if (str(rows[0][1]) != str(username) or str(rows[0][2]) != str(computer) or str(rows[0][3]) != str(speed)):
            # Имя пользователя меняется на другое имя, не на * и меняется группа скорости
            if str(username) != '*' or (str(username) == '*' and str(rows[0][3]) != str(speed) and str(rows[0][1]) == str(username)):
              try:
                cursor.execute("update users set username = %s, computer = %s, speed = %s where ip = %s;", (username, computer, speed, ip_addr,))
              except psycopg2.DatabaseError as error:
                log_write(error)
                sys.exit(1)
              # Подготовка данных для лога
              if str(rows[0][1]) != str(username):
                username = str(rows[0][1])+'->'+str(username)
              if str(rows[0][2]) != str(computer):
                computer = str(rows[0][2])+'->'+str(computer)
              if str(rows[0][3]) != str(speed):
                speed = str(rows[0][3])+'->'+str(speed)
              # Запись в лог файл
              log_write('Update '+ip_addr+' '+username+' '+computer+' '+speed)
          #
          # Если изменилось имя пользователя (* не учитывается), тогда запишем ip адрес в подозрение на терминальный сервер
          if str(rows[0][1]) != str(username) and str(username) != '*' and str(rows[0][1]) != '*':
            if self.ip_terminals.count(ip_addr) < 2:
              self.ip_terminals.append(ip_addr)
            # Это терминальный сервер
            if self.ip_terminals.count(ip_addr) > 1:
              # Удаляем все записи о данном сервере из листа повторений
              while self.ip_terminals.count(ip_addr) > 0:
                try:
                  self.ip_terminals.remove(ip_addr)
                except:
                  pass
              try:
                # Запрещаем доступ с терминального сервера
                cursor.execute("update users set access = 'no' where ip = %s;", ( ip_addr,))
              except psycopg2.DatabaseError as error:
                log_write(error)
                sys.exit(1)
              # Запись в лог файл
              log_write('Detect '+ip_addr+' is many users, block ip address')
              #
          # Комит всех транзакций
          conn_pg.commit()
        # Закрытие курсора
        cursor.close()
      # Ожидание потока
      for tick in range(5):
        if app_work.empty():
          break
        time.sleep(1)
    conn_pg.close()
    # Запись в лог файл
    log_write('Thread track_events stopped')
    # Удаление потока из списка
    self.threads_list.get()

#------------------------------------------------------------------------------------------------

# Класс для работы с сетевыми пакетами
class sniff_packets(Thread):
  # Стартовые параметры
  def  __init__(self, threads_list, todolist):
    super().__init__()
    self.socket = None
    self.daemon = True
    self.threads_list = threads_list
    self.todolist = todolist
    self.ip_clients = []
    self.ip_local = get_ip_local()

  # Обработчик ip
  def work_with_ip(self, todolist):
    # Добавление в очередь потока
    self.threads_list.put('thread')
    # Запись в лог файл
    log_write('Thread work_with_ip running')
    while not app_work.empty():
      # Очистка списка ip адресов
      if self.todolist.empty():
        self.ip_clients.clear()
      # Ожидание потока
      for tick in range(5):
        time.sleep(1)
        if app_work.empty():
          break
    # Запись в лог файл
    log_write('Thread work_with_ip stopped')
    # Удаление потока из списка
    self.threads_list.get()

  # Обработчик каждого сетевого пакета
  def work_with_packet(self, packet):
    # Проверка пакета на валидность и что ip адрес источника не сам сервер
    if IP in packet[0] and packet[1].src not in self.ip_local:
      # Проверка, что адрес источника находится в локальной сети
      if packet[1].src.find(get_config('ADUserIPMask'))!=-1:
        # Проверка, что ip адреса ещё нет в списке
        if packet[1].src not in self.ip_clients:
          # Получаем ip адрес
          ip_addr = packet[1].src
          # Добавляем ip адрес в список новых клиентов
          self.ip_clients.append(ip_addr)
          # Добавляем ip адрес в очередь
          todolist.put(ip_addr)

  # Главный модуль выполнения потока
  def run(self):
    # Запуск потока обработки ip
    threading.Thread(target=self.work_with_ip, args=(todolist,)).start()
    # Запуск обработчика пакетов
    self.socket = conf.L2listen(type=ETH_P_ALL, filter="ip")
    sniff(opened_socket=self.socket, iface=get_config('LANInterface'), prn=self.work_with_packet, store=0)

#------------------------------------------------------------------------------------------------

# Запуск всех компонентов сервера
if __name__ =='__main__':
  # Настройка обработчика завершения приложения для системного SIGTERM и Ctrl+C (SIGINT)
  signal.signal(signal.SIGTERM, signal_hundler)
  signal.signal(signal.SIGINT, signal_hundler)
  # Начальная инициализация и проверка
  init_server()
  # Создание очереди заданий для потоков
  todolist = Queue()
  # Создание очереди состояния работы потоков
  threads_list = Queue()
  # Создание очереди завершения приложения
  app_work = Queue()
  app_work.put('run')
  # Запуск потока обработки сетевых пакетов
  sniff_packets(threads_list,todolist).start()
  # Запуск потока чтения данных из AD
  track_events(threads_list,todolist).start()
  # Запуск потока изменений в nftables
  setup_nftables(threads_list,todolist).start()
  # Запуск потока чтения трафика из nftables
  traffic_nftables(threads_list,todolist).start()
  #
  # Главный цикл работы программы
  while not threads_list.empty():
    time.sleep(0.1)
