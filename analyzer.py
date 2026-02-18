import argparse
import socket
import random
import time
import re
import gzip
import io
from urllib.parse import urlparse
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap


# -------------------------
# Utils
# -------------------------
XSS_PATTERNS = [
    r"<script\b",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"<img\b",
]
XSS_RE = re.compile("|".join(XSS_PATTERNS), re.IGNORECASE)


def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None


def parse_url(url_arg):
    """Парсит URL и извлекает hostname, path и scheme."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg

    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        if parsed.query:
            path = f"{path}?{parsed.query}"
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None


def _split_http(raw_bytes: bytes):
    """
    Пытается отделить заголовки HTTP от тела:
    возвращает (start_line, headers_dict, body_bytes) или (None, None, None).
    """
    if not raw_bytes:
        return None, None, None

    marker = b"\r\n\r\n"
    if marker not in raw_bytes:
        return None, None, None

    head, body = raw_bytes.split(marker, 1)
    lines = head.split(b"\r\n")
    if not lines:
        return None, None, None

    start_line = lines[0].decode("iso-8859-1", errors="ignore")
    headers = {}
    for ln in lines[1:]:
        try:
            s = ln.decode("iso-8859-1", errors="ignore")
            if ":" in s:
                k, v = s.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        except Exception:
            pass

    return start_line, headers, body


def _maybe_gunzip(body: bytes, headers: dict):
    """
    Если ответ сжат gzip — распаковываем.
    """
    if not body or not headers:
        return body

    enc = headers.get("content-encoding", "").lower()
    if "gzip" in enc:
        try:
            return gzip.decompress(body)
        except Exception:
            # иногда gzip поток "нестандартный" — пробуем через GzipFile
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as gf:
                    return gf.read()
            except Exception:
                return body
    return body


def _safe_decode(b: bytes):
    if b is None:
        return ""
    for enc in ("utf-8", "cp1251", "iso-8859-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="ignore")


def _is_http_message(start_line: str):
    if not start_line:
        return False
    # Request line: GET / HTTP/1.1  |  POST /...
    if start_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
        return True
    # Response line: HTTP/1.1 200 OK
    if start_line.startswith("HTTP/"):
        return True
    return False


def _find_xss_in_text(text: str):
    if not text:
        return False
    return bool(XSS_RE.search(text))


# -------------------------
# Stage 3: optional raw HTTP send (as in your template)
# -------------------------
def send_http_request(hostname, path, custom_request=None):
    """Отправляет HTTP-запрос через Scapy (базово)."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    port = 80
    client_sport = random.randint(1025, 65500)

    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'

    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)

    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"Не удалось установить соединение с {hostname}")
        return None

    client_seq = syn_ack[TCP].ack
    client_ack = syn_ack[TCP].seq + 1
    ack_packet = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='A'
    )
    send(ack_packet, verbose=False)

    time.sleep(0.1)

    http_request = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='PA'
    ) / http_request_str

    send(http_request, verbose=False)

    return dest_ip, port, client_sport


# -------------------------
# Stage 2: capture
# -------------------------
def capture_traffic(hostname, timeout=30, output_file=None, iface=None):
    """Перехватывает HTTP-трафик (tcp/80) для указанного хоста."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    print(f"[+] Начало перехвата трафика для {hostname} ({dest_ip})...")
    print(f"[i] Таймаут: {timeout} сек")
    if iface:
        print(f"[i] Интерфейс: {iface}")

    bpf = f"tcp port 80 and host {dest_ip}"
    print(f"[i] BPF-фильтр: {bpf}")

    packets = sniff(filter=bpf, timeout=timeout, iface=iface, store=True)

    print(f"[+] Перехвачено пакетов: {len(packets)}")

    if output_file and len(packets) > 0:
        wrpcap(output_file, packets)
        print(f"[+] Трафик сохранён в: {output_file}")

    return packets


# -------------------------
# Stage 2/4: analyze
# -------------------------
def analyze_packets(packets, show_limit=10):
    """Анализирует пакеты: HTTP-запросы/ответы, gzip, XSS payload + reflection."""
    if not packets:
        print("[-] Нет пакетов для анализа")
        return

    http_msgs = []
    for pkt in packets:
        if pkt.haslayer('Raw'):
            raw_bytes = bytes(pkt['Raw'].load)
            start_line, headers, body = _split_http(raw_bytes)
            if not start_line or not _is_http_message(start_line):
                continue

            # если это response и gzip — распаковать тело
            body2 = _maybe_gunzip(body, headers)
            body_text = _safe_decode(body2)

            http_msgs.append({
                "start": start_line,
                "headers": headers,
                "body_text": body_text,
                "raw_head": _safe_decode(raw_bytes[: min(len(raw_bytes), 600)]),
            })

    print(f"[+] Найдено HTTP-сообщений: {len(http_msgs)}")

    # 1) показать несколько первых сообщений (как в твоём шаблоне, но аккуратнее)
    for i, msg in enumerate(http_msgs[:show_limit], 1):
        print("\n" + "=" * 80)
        print(f"HTTP-сообщение #{i}")
        print(f"Start-Line: {msg['start']}")
        print("Заголовки (частично):")
        for k in list(msg["headers"].keys())[:12]:
            print(f"  {k}: {msg['headers'][k]}")
        print("\nRaw (первые ~600 символов):")
        print(msg["raw_head"])

    # 2) этап 4: поиск XSS в запросах + отражение в ответах
    xss_requests = []
    responses = []

    for msg in http_msgs:
        if msg["start"].startswith(("GET ", "POST ")):
            # ищем payload в стартовой строке и теле (для POST)
            hay = msg["start"] + "\n\n" + msg["body_text"]
            if _find_xss_in_text(hay):
                xss_requests.append(msg)
        elif msg["start"].startswith("HTTP/"):
            responses.append(msg)

    print("\n" + "-" * 80)
    print(f"[+] Запросов с признаками XSS payload: {len(xss_requests)}")

    # Отражение: есть ли тот же кусок payload в ответе
    # (упрощённо: ищем совпадения по сигнатурам)
    reflected_hits = 0
    for req in xss_requests:
        # пытаемся вытащить "кусок" payload (самое вероятное)
        req_text = req["start"] + "\n" + req["body_text"]
        # примитивно: берём строки где есть xss-сигнатуры
        candidates = []
        for line in req_text.splitlines():
            if _find_xss_in_text(line):
                candidates.append(line.strip())
        # если кандидатов нет — проверяем всё целиком
        if not candidates:
            candidates = [req_text]

        for resp in responses:
            resp_text = resp["body_text"]
            if not resp_text:
                continue
            # проверяем, отражается ли что-то похожее
            if any(c and c[:80] in resp_text for c in candidates if len(c) >= 10):
                reflected_hits += 1
                break

    print(f"[+] Ответов с признаками отражения payload (эвристика): {reflected_hits}")

    print("\n[i] Что смотреть руками для отчёта (этап 4):")
    print("    • В запросе: GET или POST, где именно payload (URL-параметр/тело формы).")
    print("    • В ответе: находится ли payload в HTML-теле/атрибуте/JS и т.д.")
    print("    • Сравнить обычный ответ vs ответ при атаке (структура/контент).")


def analyze_saved_traffic(pcap_file):
    """Анализирует сохранённый трафик из .pcap файла."""
    print(f"[+] Анализ трафика из файла: {pcap_file}")
    packets = rdpcap(pcap_file)
    analyze_packets(packets)


def main():
    parser = argparse.ArgumentParser(
        description='Анализ HTTP-трафика и следов XSS с использованием Scapy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Перехват трафика (WSL)
  sudo python3 scapy_xss_analyzer.py --capture google-gruyere.appspot.com --timeout 60 --output traffic.pcap

  # Перехват с указанием интерфейса
  sudo python3 scapy_xss_analyzer.py --capture google-gruyere.appspot.com --timeout 60 --iface eth0 --output traffic.pcap

  # Анализ сохранённого pcap
  python3 scapy_xss_analyzer.py --analyze traffic.pcap
        """
    )

    parser.add_argument('--send', metavar='URL', help='Отправить HTTP-запрос на указанный URL')
    parser.add_argument('--capture', metavar='HOSTNAME', help='Перехватить трафик для указанного хоста')
    parser.add_argument('--analyze', metavar='PCAP_FILE', help='Проанализировать сохранённый трафик из .pcap файла')

    parser.add_argument('--timeout', type=int, default=30, help='Таймаут перехвата в секундах (по умолчанию 30)')
    parser.add_argument('--output', metavar='FILE', help='Файл для сохранения перехваченного трафика (.pcap)')
    parser.add_argument('--iface', metavar='IFACE', help='Интерфейс (например eth0 в WSL)')

    parser.add_argument('--request', metavar='HTTP_REQUEST', help='Кастомный HTTP-запрос (опционально)')

    args = parser.parse_args()

    if not any([args.send, args.capture, args.analyze]):
        parser.print_help()
        return

    if args.send:
        hostname, path, scheme = parse_url(args.send)
        if not hostname:
            print("[-] Ошибка: не удалось распарсить URL")
            return
        print(f"[+] Отправка HTTP-запроса на {hostname}{path}")
        result = send_http_request(hostname, path, args.request)
        print("[+]" if result else "[-]", "HTTP-запрос отправлен" if result else "Ошибка при отправке HTTP-запроса")

    if args.capture:
        packets = capture_traffic(args.capture, args.timeout, args.output, args.iface)
        if packets:
            analyze_packets(packets)

    if args.analyze:
        analyze_saved_traffic(args.analyze)


if __name__ == '__main__':
    main()
