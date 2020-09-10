#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

# Встроенные модули
import time, sys, socket
from threading import Thread

# Внешние модули
try:
  from scapy.all import *
except ModuleNotFoundError as err:
  print(err)
  sys.exit(1)

# Внутренние модули
try:
  from mod_common import *
except ModuleNotFoundError as err:
  print(err)
  sys.exit(1)

# Класс для работы с сетевыми пакетами
class getting_packets(Thread):
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
    # Запись в лог файл
    log_write('Thread work_with_ip running')
    while not app_work.empty():
      # Очистка списка ip адресов
      if self.todolist.empty():
        self.ip_clients.clear()
      # Ожидание потока
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
      if packet[1].src.find(get_config('ADUserIPMask')) != -1:
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
