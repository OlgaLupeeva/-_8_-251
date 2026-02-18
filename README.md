# ДЗ 8 — Перехват HTTP-трафика и анализ XSS (Scapy)

## Цель

Реализовать перехват HTTP-трафика и выполнить анализ возможных XSS-пейлоадов:

- перехватить обычный HTTP-трафик;
- сохранить его в формате `.pcap`;
- выделить HTTP-сообщения;
- обнаружить XSS-payload в запросах;
- проанализировать структуру ответа сервера.

---

## Используемые технологии

- Python 3
- Scapy
- WSL (Ubuntu)
- tcpdump
- Google Gruyere (HTTP)

---

## Как запустить

```bash
# установка зависимостей
pip install -r requirements.txt

# перехват обычного трафика
sudo ./venv/bin/python analyzer.py \
  --capture google-gruyere.appspot.com \
  --timeout 120 \
  --iface eth0 \
  --output normal_traffic.pcap

# перехват XSS-запроса
sudo ./venv/bin/python analyzer.py \
  --capture google-gruyere.appspot.com \
  --timeout 180 \
  --iface eth0 \
  --output xss_traffic.pcap

# анализ сохранённого трафика
./venv/bin/python analyzer.py --analyze xss_traffic.pcap
