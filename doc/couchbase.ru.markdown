# Nginx Couchbase Module (0.2.0)

Клиент к [Couchbase][1] для [nginx][2].

## Описание

Модуль транслирует запросы к кластеру Couchbase, заданному аргументом
директивы [couchbase_pass][3], и возвращает результат обратно клиенту.

По умолчанию, модуль может использовать информацию, доступную в
запросе, чтобы сформировать пакет данных. В качестве ключа,
используется часть URI, оставшаяся после отсечения совпавшей части
location.

    location /cache/ {
        couchbase_pass;
    }

В примере выше, если у сервера будет запрошен адрес
`/cache/example.html`, то ключом будет `example.html`.

Чтобы выбрать команду, оправляемую на Couchbase Server, используется
HTTP method. Таблица ниже показывает соответствие команд методам.

<table>
  <tr><th>HTTP</th><th>Couchbase</th></tr>
  <tr><td>GET, HEAD</td><td>get</td></tr>
  <tr><td>POST</td><td>add</td></tr>
  <tr><td>PUT</td><td>set</td></tr>
  <tr><td>DELETE</td><td>delete</td></tr>
</table>

И, наконец, для того, чтобы выбрать значение (для операций, изменяющих
его) ипользуется тело HTTP запроса.

Информацию о том, как можно переопределить вышеприведённое поведение с
помощью переменных, можно найти ниже: [set $couchbase_cmd][4], [set
$couchbase_key][5], [set $couchbase_val][6].

## Директивы конфигурации

<a name="couchbase_pass"></a>
<table>
  <tr>
    <td><strong>синтаксис:</strong></td>
    <td><code><strong>couchbase_pass</strong> <i>address</i> bucket=<i>value</i> username=<i>value</i> password=<i>value</i>;</code></td>
  </tr>
  <tr>
    <td><strong>значение по умолчанию:</strong></td>
    <td><code><strong>couchbase_pass</strong> <i>localhost:8091</i> bucket=<i>default</i>;</code></td>
  </tr>
  <tr>
    <td><strong>строгость:</strong></td>
    <td>обязательная</td>
  </tr>
  <tr>
    <td><strong>контекст:</strong></td>
    <td><code>location</code>, <code>if in location</code>, <code>limit_except</code></td>
  </tr>
</table>

Задаёт параметры для подключения к кластеру. Параметр `address`
представляет собой пары `host:port`, разделённые запятой, причём
`:port` может быть опущен, тогда будет использован порт по умолчанию:
8091.

    location /cache/ {
        couchbase_pass example.com:8091,example.org bucket=app;
    }

* * *

<a name="couchbase_connect_timeout"></a>
<table>
  <tr>
    <td><strong>синтаксис:</strong></td>
    <td><code><strong>couchbase_connect_timeout</strong> <i>время</i>;</code></td>
  </tr>
  <tr>
    <td><strong>значение по умолчанию:</strong></td>
    <td><code><strong>couchbase_connect_timeout</strong> <i>2.5s</i>;</code></td>
  </tr>
  <tr>
    <td><strong>строгость:</strong></td>
    <td>необязательная</td>
  </tr>
  <tr>
    <td><strong>контекст:</strong></td>
    <td><code>location</code></td>
  </tr>
</table>

Задаёт таймаут для установки подключения к Couchbase Server.

* * *

<a name="couchbase_timeout"></a>
<table>
  <tr>
    <td><strong>синтаксис:</strong></td>
    <td><code><strong>couchbase_timeout</strong> <i>время</i>;</code></td>
  </tr>
  <tr>
    <td><strong>значение по умолчанию:</strong></td>
    <td><code><strong>couchbase_timeout</strong> <i>2.5s</i>;</code></td>
  </tr>
  <tr>
    <td><strong>строгость:</strong></td>
    <td>необязательная</td>
  </tr>
  <tr>
    <td><strong>контекст:</strong></td>
    <td><code>location</code></td>
  </tr>
</table>

Задаёт таймаут для операций обмена данными с Couchbase Server.

## Переменные

<a name="set-couchbase_cmd"></a>
<table>
  <tr>
    <td><strong>синтаксис:</strong></td>
    <td><code><strong>set $couchbase_cmd</strong> <i>команда</i>;</code></td>
  </tr>
  <tr>
    <td><strong>значение по умолчанию:</strong></td>
    <td>-</td>
  </tr>
  <tr>
    <td><strong>строгость:</strong></td>
    <td>необязательная</td>
  </tr>
</table>

Устанавливает тип команды, выполняемой для данного location. Например,
команда может быть получена из query string (`/cache/?cmd=append`):

    location /cache/ {
        set $couchbase_cmd $arg_cmd;
        couchbase_pass;
    }

Или можно зафиксировать команду в виде строки:

    location /cache/ {
        set $couchbase_cmd 'append';
        couchbase_pass;
    }

Для версии 0.2.0 поддерживается следующий набор команд: `get`, `set`,
`add`, `replace`, `append`, `prepend`, `delete`. Про соответствие HTTP
методов командам можно прочитать выше в разделе "Описание".

* * *

<a name="set-couchbase_key"></a>
<table>
  <tr>
    <td><strong>синтаксис:</strong></td>
    <td><code><strong>set $couchbase_key</strong> <i>значение</i>;</code></td>
  </tr>
  <tr>
    <td><strong>значение по умолчанию:</strong></td>
    <td>-</td>
  </tr>
  <tr>
    <td><strong>строгость:</strong></td>
    <td>необязательная</td>
  </tr>
</table>

Управляет выбором ключа для документа. Например, ключ может быть
получен из query string (`/cache/?key=foo`):

    location /cache/ {
        set $couchbase_key $arg_key;
        couchbase_pass;
    }

Или можно зафиксировать ключ в виде строки:

    location /cache/ {
        set $couchbase_key 'foo';
        couchbase_pass;
    }

* * *

<a name="set-couchbase_val"></a>
<table>
  <tr>
    <td><strong>синтаксис:</strong></td>
    <td><code><strong>set $couchbase_val</strong> <i>значение</i>;</code></td>
  </tr>
  <tr>
    <td><strong>значение по умолчанию:</strong></td>
    <td>-</td>
  </tr>
  <tr>
    <td><strong>строгость:</strong></td>
    <td>необязательная</td>
  </tr>
</table>

Управляет выбором значения для документа. Например, значение может быть
получено из query string (`/cache/?value=foo%0a`):

    location /cache/ {
        set $couchbase_val $arg_val;
        couchbase_pass;
    }

Или можно зафиксировать значение в виде строки:

    location /cache/ {
        set $couchbase_val 'foo%a';
        couchbase_pass;
    }

Обратите внимание, что если значение приходит из переменной
`$couchbase_key`, оно будет переведено из URL-кодировки.

* * *

<a name="set-couchbase_cas"></a>
<table>
  <tr>
    <td><strong>синтаксис:</strong></td>
    <td><code><strong>set $couchbase_cas</strong> <i>значение</i>;</code></td>
  </tr>
  <tr>
    <td><strong>значение по умолчанию:</strong></td>
    <td>-</td>
  </tr>
  <tr>
    <td><strong>строгость:</strong></td>
    <td>необязательная</td>
  </tr>
</table>

Переменная хранит CAS значение документа. Это значение меняется при
каждом изменении документа. Таким образом его можно использовать для
оптимистический блокировки.

    location /cache/ {
        set $couchbase_key $arg_key;
        set $couchbase_val $arg_val;
        set $couchbase_cmd $arg_cmd;
        set $couchbase_cas $arg_cas;
        couchbase_pass;
        add_header X-CAS $couchbase_cas;
    }

С такой конфигурацией для каждой операции будет установлен заголовок
<code>X-CAS</code> со актуальным значением CAS. Это значение может
быть использовано при последующем обновлении, и в случае, если кто-то
успел изменить его, будет выдан код <code>409 Conflict</code>, так что
клиент должен будет обновить локальный документ и попробовать ещё с
новым CAS.

## Системные требования

Данный модуль тестировался на совместимость с версией nginx 1.3.7.

## Скачать

Последняя версия 0.2.0: [nginx-couchbase-module-0.2.0.tar.gz][7].

Репозиторий проекта: [https://github.com/couchbaselabs/couchbase-nginx-module][8]

## Как использовать

Создать директорию для сборки, скачать и распаковать туда все
зависимости:

    mkdir nginx-couchbase
    cd nginx-couchbase
    wget http://nginx.org/download/nginx-1.3.7.tar.gz
    wget http://packages.couchbase.com/clients/c/libcouchbase-2.0.3nginx2.tar.gz
    wget http://packages.couchbase.com/clients/c/nginx-couchbase-module-0.2.0.tar.gz
    for i in *.tar.gz; do tar xvf $i; done

Последовательность шагов ниже установит nginx с модулем в директорию
`/opt/nginx-couchbase`:

    export PREFIX=/opt/nginx-couchbase

    cd libcouchbase-2.0.3nginx2
    ./configure --prefix=$PREFIX --enable-debug --disable-plugins --disable-tests --disable-couchbasemock
    make && sudo make install
    cd ..

    cd nginx-1.3.7
    export LIBCOUCHBASE_INCLUDE=$PREFIX/include
    export LIBCOUCHBASE_LIB=$PREFIX/lib
    ./configure --prefix=$PREFIX --with-debug --add-module=../nginx-couchbase-module-0.2.0
    make && sudo make install


[1]: http://couchbase.com/download
[2]: http://www.nginx.ru/
[3]: #couchbase_pass
[4]: #set-couchbase_cmd
[5]: #set-couchbase_key
[6]: #set-couchbase_val
[7]: http://packages.couchbase.com/clients/c/nginx-couchbase-module-0.2.0.tar.gz
[8]: https://github.com/couchbaselabs/couchbase-nginx-module
