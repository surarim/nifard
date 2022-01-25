#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

# Встроенные модули
import time, sys, socket
from threading import Thread

# Внешние модули
try:
  import psycopg2
  from pypsrp.client import Client
except ModuleNotFoundError as err:
  print(err)
  sys.exit(1)

# Внутренние модули
try:
  from mod_common import *
except ModuleNotFoundError as err:
  print(err)
  sys.exit(1)

# Класс для получения новых клиентов
class getting_clients(Thread):
  # Стартовые параметры
  def  __init__(self, threads_list, todolist):
    super().__init__()
    self.daemon = True
    self.threads_list = threads_list
    self.todolist = todolist
    self.ip_clients = [] # Список ip адресов клиентов
    self.error = False # Ошибка вызова обработчика

  # Поток чтения журнала security и сетевых пакетов, для получения связки: ip, пользователь, имя пк
  # Затем добавление новых записей в базу данных
  def run(self):
    # Запись в лог файл
    log_write('Thread getting_clients running')
    try:
      # Подключение к базе
      conn_pg = psycopg2.connect(database='nifard', user=get_config('DatabaseUserName'), password=get_config('DatabasePassword') )
    except psycopg2.DatabaseError as error:
      log_write(error)
      sys.exit(1)
    while not app_work.empty():
      result = ''
      # Очистка списка новых клиентов
      self.ip_clients.clear()
      while not app_work.empty():
        for Server in get_config('ADServer').split():
          self.error = False
          # Подключение к серверу
          client = Client(Server+"."+get_config('DomainRealm'), auth="kerberos", ssl=False, username=get_config('ADUserName'), password=get_config('ADUserPassword'))
          # Получение журнала security по событию 4624, фильтрация по пользователям с полями: ip адрес, имя пользователя, домен
          script = """Get-EventLog -LogName security -ComputerName """+Server+""" -Newest 200 -InstanceId 4624 | Where-Object {($_.ReplacementStrings[5] -notlike '*$*') -and ($_.ReplacementStrings[5] -notlike '*/*') -and ($_.ReplacementStrings[5] -notlike '*АНОНИМ*') -and ($_.ReplacementStrings[18] -notlike '*-*')} | Select-Object @{Name="IpAddress";Expression={ $_.ReplacementStrings[18]}},@{Name="UserName";Expression={ $_.ReplacementStrings[5]}},@{Name="Domain";Expression={ $_.ReplacementStrings[6]}} -Unique"""
          try:
            result, streams, had_error = client.execute_ps(script)
          except:
            log_write('Get-EventLog powershell error')
            self.error = True
            if app_work.empty(): break # Повторная проверка на завершение потока
            time.sleep(5)
          if not self.error:
            break
        if not self.error:
          break
      #
      # Цикл добавления клиентов, полученных из журнала, в список
      for line in result.splitlines():
        if line.find(get_config('ADUserIPMask')) != -1 and line not in self.ip_clients:
          # Получение параметров клиента
          ip_addr = line.split()[0] # IP адрес клиента
          username = line.split()[1] # Имя пользователя
          domain = line.split()[2].lower()+get_config('DomainRealm')[get_config('DomainRealm').find('.'):] # Домен, с корректировкой по конфигу
          try:
            computer = socket.gethostbyaddr(ip_addr)[0] # Имя компьютера
            computer = computer[0:computer.find('.')] if computer.find('.') != -1 else computer  # Имя компьютера без доменной части
          except OSError:
            computer = '*' # Не получено имя компьютера
            pass
          if computer == '':
            computer = '*'
          # Добавление нового клиента в список
          self.ip_clients.append(ip_addr)
          self.ip_clients.append(username)
          self.ip_clients.append(computer)
          self.ip_clients.append(domain)
      #
      if app_work.empty(): break # Повторная проверка на завершение потока
      #
      # Цикл добавления клиентов, полученных из очереди, в список
      while not self.todolist.empty():
        ip_addr = self.todolist.get() # IP адрес клиента
        # Проверка, что ip адреса ещё нет в списке
        if ip_addr not in self.ip_clients:
          username = '*' # Имя пользователя неизвестно
          computer = '*' # Имя компьютера неизвестно
          domain = 'Domain Unknown' # Домен не известен
          try:
            computer = socket.gethostbyaddr(ip_addr)[0] # Имя компьютера
          except OSError:
            pass
          if computer.find('.') != -1:
            domain = computer[computer.find('.')+1:]  # Имя домена
            computer = computer[0:computer.find('.')] # Имя компьютера без доменной части
          # Добавление нового клиента в список
          self.ip_clients.append(ip_addr)
          self.ip_clients.append(username)
          self.ip_clients.append(computer)
          self.ip_clients.append(domain)
      log_write('Newest '+str(len(self.ip_clients)//4)+' ip addresses')
      #
      # Цикл добавления новых клиентов в базу
      for pos in range(0,len(self.ip_clients),4):
        ip_addr = self.ip_clients[pos] # IP адрес клиента
        username = self.ip_clients[pos+1] # Имя пользователя
        computer = self.ip_clients[pos+2]  # Имя компьютера
        domain = self.ip_clients[pos+3]  # Имя домена
        osversion = ''
        speed_computer = 'disable'
      #
        # Проверка операционной системы компьютера
        while not app_work.empty():
          for Server in get_config('ADServer').split():
            self.error = False
            # Подключение к серверу
            client = Client(Server+"."+get_config('DomainRealm'), auth="kerberos", ssl=False, username=get_config('ADUserName'), password=get_config('ADUserPassword'))
            # Проверка операционной системы компьютера
            script = """([ADSISEARCHER]'cn="""+computer+"""').Findone().Properties.operatingsystem"""
            try:
              osversion, streams, had_error = client.execute_ps(script)
            except:
              log_write('[ADSISEARCHER] Operatingsystem powershell error')
              self.error = True
              if app_work.empty(): break # Повторная проверка на завершение потока
              time.sleep(5)
            if not self.error:
              break
          if not self.error:
            break
        if not osversion:
          osversion = 'OS Unknown'
        #
        # Получение скорости для текущего компьютера
        for Server in get_config('ADServer').split():
          self.error = False
          time.sleep(5)
          # Подключение к серверу
          client = Client(Server+"."+get_config('DomainRealm'), auth="kerberos", ssl=False, username=get_config('ADUserName'), password=get_config('ADUserPassword'))
          # Получение скорости для текущего компьютера в верхнем регистре (фильтрация по группе доступа в Интернет)
          script = """([ADSISEARCHER]'cn="""+computer+"""').Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1' -like '"""+get_config('ADGroupInternetMask')+"""*'"""
          try:
            speed, streams, had_error = client.execute_ps(script)
          except:
            log_write('[ADSISEARCHER] Memberof(Computer Internet) powershell error')
            self.error = True
          if self.error or app_work.empty(): break
        try:
          # Установка результирующей группы скорости
          speed_computer = speed.split()[0]
          if speed_computer == 'False': speed_computer = 'disable'
        except:
          speed_computer = 'disable'
        #
        # Запись в лог файл
        log_write('Newest '+ip_addr+' '+username+' '+computer+'['+domain+']'+' speed['+speed_computer+'] ('+osversion+')')
        if app_work.empty(): break # Повторная проверка на завершение потока
        #
        # Поиск в базе выбранного ip адреса
        cursor = conn_pg.cursor()
        try:
          cursor.execute("select * from users where ip = %s;", (ip_addr,))
        except psycopg2.DatabaseError as error:
          log_write(error)
          sys.exit(1)
        rows = cursor.fetchall()
        for row in rows:
          ip_addr_db = row[0] # IP адрес из базы
          username_db = row[1] # Имя пользователя из базы
          computer_db = row[2] # Имя компьютера из базы
          domain_db = row[3] # Имя домена из базы
          speed_db = row[4] # Группа скорости из базы
          break
        #
        # Если ip адреса нет в базе, добавляем
        if not rows:
          try:
            cursor.execute("insert into users values (%s, %s, %s, %s, %s, 0);", (ip_addr, username, computer, domain, speed_computer,))
          except psycopg2.DatabaseError as error:
            log_write(error)
            sys.exit(1)
          # Запись в лог файл
          log_write('Insert '+ip_addr+' '+username+' '+computer+' '+speed_computer)
          conn_pg.commit()
        #
        if rows:
          # Если изменилось имя пользователя, имя компьютера, имя домена или группа скорости
          # При этом имя пользователя, компьютера или домена, меняется только на другое имя (не на '*')
          update_log = ''
          if str(username) != str(username_db) and str(username) != '*':
            update_log = update_log+' '+str(username_db)+'->'+ str(username)
            username_db = username
          if str(computer) != str(computer_db) and str(computer) != '*':
            update_log = update_log+' '+str(computer_db)+'->'+ str(computer)
            computer_db = computer
          if str(domain) != str(domain_db) and str(domain) != 'Domain Unknown':
            update_log = update_log+' '+str(domain_db)+'->'+ str(domain)
            domain_db = domain
          if str(speed_computer) != str(speed_db):
            update_log = update_log+' '+str(speed_db)+'->'+ str(speed_computer)
            speed_db = speed_computer
          try:
            # Запись в лог файл, если что-то изменилось в базе
            if update_log != '':
              cursor.execute("update users set username = %s, computer = %s, domain = %s, speed = %s where ip = %s;", (username_db, computer_db, domain_db, speed_db, ip_addr,))
              log_write('Update '+ip_addr+update_log)
          except psycopg2.DatabaseError as error:
            log_write(error)
            sys.exit(1)
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
    log_write('Thread getting_clients stopped')
    # Удаление потока из списка
    self.threads_list.get()
