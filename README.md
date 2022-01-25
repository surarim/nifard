![Alt text](nifard.png?raw=true "Title")
# nifard
### Интернет маршрутизатор с прозрачным доступом
### Version 0.81 (development)
<hr>
Маршрутизатор предоставляет доступ в Интернет по ip адресам клиентов, с параллельной проверкой их скорости через службу каталогов Active Directory и мониторинг обращений. Предоставление доступа для ip адресов производится через правила nftables, а проверка параметров клиентов происходит автоматически через модули pypsrp и scapy.
<br>
Протестировано и собрано с использованием следующих компонентов:
<ul>
  <li>Python: 3.10.2</li>
  <li>PostgreSQL: 14.1</li>
  <li>nftables: 1.0.1</li>
  <li>psycopg2: 2.9.3</li>
  <li>pypsrp: 0.7.0</li>
  <li>scapy: 2.4.5</li>
 </ul>
