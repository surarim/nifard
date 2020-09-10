#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

# Встроенные модули
import time, sys, signal

# Внутренние модули
try:
  from mod_common import *
  from mod_setup_nftables import setup_nftables
  from mod_traffic_nftables import traffic_nftables
  from mod_getting_clients import getting_clients
  from mod_getting_packets import getting_packets
except ModuleNotFoundError as err:
  print(err)
  sys.exit(1)

#------------------------------------------------------------------------------------------------

# Запуск всех компонентов сервера
if __name__ =='__main__':
  # Начальная инициализация и проверка
  init_server()
  # Настройка обработчика завершения приложения для системного SIGTERM и Ctrl+C (SIGINT)
  signal.signal(signal.SIGTERM, signal_hundler)
  signal.signal(signal.SIGINT, signal_hundler)
  # Запуск потока обработки сетевых пакетов
  # Добавление в очередь потока
  threads_list.put('thread')
  getting_packets(threads_list,todolist).start()
  # Запуск потока обнаружения новых клиентов
  threads_list.put('thread')
  getting_clients(threads_list,todolist).start()
  # Запуск потока изменений в nftables
  threads_list.put('thread')
  setup_nftables(threads_list,todolist).start()
  # Запуск потока чтения трафика из nftables
  threads_list.put('thread')
  traffic_nftables(threads_list,todolist).start()
  #
  # Главный цикл работы программы
  while not threads_list.empty():
    time.sleep(0.1)
