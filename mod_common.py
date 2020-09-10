#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

# Встроенные модули
import os, sys, subprocess, signal
from datetime import datetime
from multiprocessing import Queue

config = [] # Список параметров файла конфигурации
todolist = Queue() # Создание очереди заданий для потоков
threads_list = Queue() # Создание очереди состояния работы потоков
app_work = Queue() # Создание очереди завершения приложения

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
  else:
    # Проверка размера лог файла
    log_size = os.path.getsize(get_config('LogFile'))
    # Если лог файл больще 10М, делаем ротацию
    if log_size > 1024**2*10:
      try:
        os.remove(get_config('LogFile')+'.old')
      except:
        pass
      os.rename(get_config('LogFile'), get_config('LogFile')+'.old')
  # Запись в лог файл
  with open(get_config('LogFile'),'a') as logfile:
    # Проверка на запуск сервера
    if message.find('Init') == -1:
      logfile.write(str(datetime.now()).split('.')[0]+' '+message+'\n')
    else:
      logfile.write('-'*110+'\n')
      logfile.write(str(datetime.now()).split('.')[0]+' '+message+'\n')

#------------------------------------------------------------------------------------------------

# Функция получения значений параметров конфигурации
def get_config(key):
  global config
  result = ''
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
          # Получение параметра
          config.append(param[0].strip())
          config.append(param[1].strip())
  try:
    result = config[config.index(key)+1]
  except ValueError as err:
    log_write('Config parameter '+str(key)+' not found, stoping server')
    sys.exit(1)
  return result

#------------------------------------------------------------------------------------------------

# Получение ip адресов самого сервера
def get_ip_local():
  try:
    ip_local = (subprocess.check_output('hostname -I', shell=True).strip()).decode().split()
  except OSError as error:
    log_write(error)
    sys.exit(1)
  return ip_local

#------------------------------------------------------------------------------------------------

# Функция инициализации настроек и среды сервера
def init_server():
  # Получение версии приложения
  try:
    readmefile = open('README.md')
  except IOError as error:
    log_write(error)
    sys.exit(1)
  for line in readmefile:
    if line.find('Version') != -1:
      version = line.split()[2]
      break
  readmefile.close()
  # Проверка на запрос версии приложения
  if len(sys.argv) > 1:
    if sys.argv[1].find('-v') != -1:
      print('version '+version)
    else:
      print('Unknown parameter '+sys.argv[1])
      print('Usage:\n -v Get version')
    sys.exit(0)
  # Проверка на существование утилиты nftables
  if subprocess.call('which nft',stdout=subprocess.PIPE, shell=True) == 1:
    print('nftables not found. Please install NFTables')
    sys.exit(1)
  # Проверка на существование утилиты psql
  if subprocess.call('which psql',stdout=subprocess.PIPE, shell=True) == 1:
    print('psql not found. Please install PostgreSQL')
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
  # Запуск основного потока завершён
  log_write('Init Server version '+version)
  app_work.put('run')
