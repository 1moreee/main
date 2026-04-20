import csv
import random

# Налаштування
filename = "test_traffic.csv"
normal_packets_count = 500  # Нормальний фоновий трафік
anomaly_packets_count = 1500 # Аномальний трафік (DDoS) від одного хакера
attacker_ip = "192.168.1.99" # IP-адреса "зловмисника"
target_ip = "10.0.0.1"       # IP-адреса жертви

protocols = ["TCP", "UDP", "ICMP"]

print(f"Починаємо генерацію файлу {filename}...")

with open(filename, mode="w", newline="") as file:
    writer = csv.writer(file)
    # Пишемо заголовки колонок (як очікує наш main.py)
    writer.writerow(["Source IP", "Destination IP", "Protocol", "Size (Bytes)"])
    
    # 1. Генеруємо НОРМАЛЬНИЙ трафік (різні випадкові IP)
    for _ in range(normal_packets_count):
        src_ip = f"192.168.1.{random.randint(1, 50)}"
        dst_ip = f"10.0.0.{random.randint(1, 10)}"
        proto = random.choice(protocols)
        size = random.randint(40, 1500)
        writer.writerow([src_ip, dst_ip, proto, size])

    # 2. Генеруємо АНОМАЛІЮ (потужний потік від однієї IP-адреси)
    for _ in range(anomaly_packets_count):
        # Хакер відправляє безліч дрібних TCP-пакетів (імітація SYN Flood)
        writer.writerow([attacker_ip, target_ip, "TCP", 64])

print(f"Готово! Згенеровано {normal_packets_count + anomaly_packets_count} рядків.")
print(f"Аномальна IP-адреса: {attacker_ip} (створено {anomaly_packets_count} пакетів).")
