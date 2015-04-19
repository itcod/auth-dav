# auth-dav
Nginx Base Authenticate url/.htpasswd for WebDAV and HTTP secure directory(links). Simple automatic search file password in directory and advanced user rights. Support CRYPT(3) MD5 SHA-1 secure hash password and permit user files. Computation in Lua (5.1)

-- Copyright (c) 2015 by Yura Vdovytchenko

"https://ihome.itcod.com/max/projects/auth-dav/",

Nginx Base Authenticate url/.htpasswd for WebDAV and HTTP secure directory(links)

Support CRYPT(3) MD5 SHA-1 secure hash.

Сomputation in Lua (5.1)

Author by Yura Vdovytchenko

License MIT

Текущая версия 15.04.19 (версия по дате публикации)

ОПИСАНИЕ

Модуль аутентификации для nginx. Написан на lua. Требуется Nginx с поддержкой lua 5.1. 
Основная задача модуля обеспечить автоматическую простую и независимую парольную защиту для каждой папки на  WEBDAV-хранилище/облаке/сайте и расширенное персональное управление правами пользователей в каждой папке отдельно. Достаточно помещать файлы паролей и прав в папки и подпапки. Реализовано методом автоматической Base-авторизации при обнаружении в папке/url файла авторизации (например: .htpasswd). Поддерживает три базовых метода кодирования паролей CRYPT(3) MD5 SHA1. Предоставляет возможность устанавливать права доступа/методы доступа, для каждого пользователя в отдельности в каждой отдельной папке.

Обязательные параметры в секции server для настройки авторизатора (пример ниже в тексте)

set $user_passwd .uhtpasswd; #user:password[crypt(3)/md5/sha1] -- файл паролей

set $user_permit .uhtpermit; #user:GET,PUT,....OPTIONS - файл разрешённых пользователям прав/методов

set $user_permit_default GET,PROPFIND,OPTIONS; # Allow -- права/методы для пользователей не имеющих персональных прав

ПРИНЦИПЫ

1. Замечания, предложения и пожелания обсуждаемы max@itcod.com (тема: auth-dav);
2. Каждой папке/подпапке собственный независимый список пользователей и возможность управления правами доступа;
3. Каждому авторизованному пользователю уникальные или общие права доступа в папках;
4. Микс общедоступных и приватных папок и подпапок;
5. Если в папке есть файл паролей $user_passwd - запрашиваем авторизацию;
6. Если в папке нет файла прав пользователей $user_permit - пользователи имеют права по умолчанию $user_permit_default;
7. Если в файле прав пользователя $user_permit отсутствует пользователь - он имеет права по умолчанию $user_permit_default;
8. Первый пользователь в файле паролей всегда администратор с всеми правами Allow;
9. Если в папке нет файла паролей то любой гость имеет права $user_permit_default;
10. Если текущий пользователь не имеет прав использовать метод выдаётся окно авторизации для входа под пользователем имеющим требуемые права;
11. Доступ к файлу паролей и прав разрешён только администратору папки (см. п.8);
12. ... в разработке ...

ЗАМЕЧАНИЯ

На текущий момент WEBDAV-клиенты (BitKenix/FAR-NetDrive) обеспечивают только авторизацию при первичном входе, и не умеют выдавать запрос авторизации при переходе в подпапку с иным авторизуемым пользователем. Браузеры умеют.

ИСТОРИЯ

YY.MM.DD (год.месяц.день)

15.04.14 - startup версия;

15.04.18 - добавлено расширеное управление разрешёнными для каждого пользователя методами (GET, POST, PUT... etc);

15.04.19 - Запретить WEBDAV и GET пользователям доступ к чтению файлам паролей $user_passwd и прав $user_permit;

ПЛАНЫ

1. расширить систему прав доступа для каждого файла в отдельности;
2. ...

ПРАВА/МЕТОДЫ ПОЛЬЗОВАТЕЛЯ В ФАЙЛЕ $user_permit 

Формат user:method1,method2,...methodN
Доступны любые существующие методы. Краткий список основных методов для WEBDAV.

GET - чтение папки/файла

PUT - публиковать файл в хранилище

PERMIT - первичный запрос WEBDAV клиента (BitKinex)

OPTIONS - запрос WEBDAV клиента (BitKinex/NetDrive)

MKCOL - создание папки

DEL - удаление папки/файла

COPY - копировать папку/файл

MOVE - переместить/переименовать папку/файл

пример1. user:GET,PERMIT,OPTIONS -- разрешает пользователю user смотреть содержимое текущей папки и заходить в эту папку по WeBDAV. Создание, удаление, переименование, копирование и перемещение папок и файлов запрещено.

пример2. user:GET,PUT,MKCOL,PERMIT,OPTIONS -- разрешает пользователю user смотреть содержимое текущей папки и заходить в эту папку по WeBDAV. Разрешает создание файлов(PUT) и создание каталогов(MKCOL). Удаление, переименование, копирование и перемещение папок и файлов запрещено.

пример3. user:GET,DEL,PERMIT,OPTIONS -- разрешает пользователю user смотреть содержимое текущей папки и заходить в эту папку по WeBDAV. Разрешает удалять папки и файлы. Создание, переименование, копирование и перемещение папок и файлов запрещено.

пример4. user:GET,PUT,MKCOL,DEL,COPY,MOVE,PERMIT,OPTIONS -- разрешает пользователю user все основные операции с файлами и папками.

REQUIRE

require "base64" -- base64.lua https://github.com/toastdriven/lua-base64

local utf8 = require "utf8" -- utf8.lua Kyle Smith https://gist.github.com/markandgo/5776124

local csv = require("csv") -- lua-csv https://github.com/geoffleyland/lua-csv

local resty_sha1 = require "resty.sha1" -- https://github.com/openresty/lua-resty-core

local apr = require "apr.core" -- lua-apr

-- Loading the library. crypt -- https://github.com/PlugwiseBV/luacrypt

descrypt = assert(package.loadlib("/usr/local/lib/lua/5.1/crypt.so", "luaopen_crypt"))


STARTUP

--path lua file: /etc/nginx/lua/auth-dav.lua

--Example Nginx virtual example.conf

server {

    listen       80;
    server_name  dav.example.com;
    server_name_in_redirect	off;
    access_log /var/log/nginx/dav.example.com-access.log main;
    #resolver 10.255.255.1 [::1]:5353;

    set $dir /opt/home;
    set $dir_path $dir;
    if ($uri ~* ^(.*)([$/].*)$) {
	set $dir_path $dir$1;
    }
    set $home $dir_path;
    set $sadm_passwd .htpsw;
    set $user_passwd .uhtpasswd; #user:password[crypt(3)/md5/sha1]
    set $user_permit .uhtpermit; #user:GET,PUT,....OPTIONS
    set $user_permit_default GET,PROPFIND,OPTIONS; # Allow

    
    location / {
	access_by_lua_file /etc/nginx/lua/auth-dav1.lua;
	dav_methods PUT DELETE MKCOL COPY MOVE;
	dav_ext_methods PROPFIND OPTIONS;
	create_full_put_path on;
	dav_access user:rw group:rw;
	client_body_temp_path /opt/itcod-dav.tmp/;
	client_max_body_size 0;
	autoindex on;
        root $dir;
        
    }
    location ~/\.ht {
	deny all;
    }
}


