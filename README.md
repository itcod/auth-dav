# auth-dav
Nginx Base Authenticate url/.htpasswd for WebDAV and HTTP secure directory(links). Support CRYPT(3) MD5 SHA-1 secure hash. Computation in Lua (5.1)

-- Copyright (c) 2015 by Yura Vdovytchenko

"https://ihome.itcod.com/max/projects/auth-dav/",

Nginx Base Authenticate url/.htpasswd for WebDAV and HTTP secure directory(links)

Support CRYPT(3) MD5 SHA-1 secure hash.

Сomputation in Lua (5.1)

Author by Yura Vdovytchenko

License MIT

Текущая версия 15.04.18 (версия по дате публикации)

ОПИСАНИЕ

Модуль аутентификации для nginx. Nginx с поддержкой lua 5.1. 
Основная задача модуля обеспечить автоматическую простую и независимую парольную защиту для каждой папки на сайте (WEBDAV-хранилище/облака). Реализовано методом автоматической Base-авторизации при обнаружении в папке/url файла авторизации (например: .htpasswd). Поддерживает три базовых метода кодирования CRYPT(3) MD5 SHA1.
Предоставляет возможность устанавливать права доступа/методы доступа, для каждого пользователя в отдельности в каждой отдельной папке.

Обязательные параметры в секции server для настройки авторизатора (пример ниже в тексте)

set $user_passwd .uhtpasswd; #user:password[crypt(3)/md5/sha1] -- файл паролей

set $user_permit .uhtpermit; #user:GET,PUT,....OPTIONS - файл разрешённых пользователям прав/методов

set $user_permit_default GET,PROPFIND,OPTIONS; # Allow -- права/методы для пользователей не имеющих персональных прав

ПРИНЦИПЫ

1. Замечания, предложения и пожелания обсуждаемы max@itcod.com (тема: auth-dav)
2. Если в папке есть файл паролей $user_passwd - запрашиваем авторизацию
3. Если в папке нет файла прав пользователей $user_permit - пользователи имеют права по умолчанию $user_permit_default
4. Если в файле прав пользователя $user_permit отсутствует пользователь - он имеет права по умолчанию $user_permit_default
5. Первый пользователь в файле паролей всегда администратор с всеми правами Allow
6. Если в папке нет файла паролей то любой гость имеет права $user_permit_default
7. Если текущий пользователь не имеет прав использовать метод выдаётся окно авторизации для входа под пользователем имеющим требуемые права
8. ... в разработке ...

ЗАМЕЧАНИЯ

На текущий момент WEBDAV-клиенты (BitKenix/FAR-NetDrive) обеспечивают только авторизацию при первичном входе, и не умеют выдавать запрос авторизации при переходе в подпапку с иным авторизуемым пользователем. Браузеры умеют.

ИСТОРИЯ

15.04.14 - первая версия

15.04.18 - добавлено расширеное управление разрешёнными для каждого пользователя методами (GET, POST, PUT... etc)

ПЛАНЫ

1. Запретить WEBDAV и GET пользователям доступ к чтению файлам паролей $user_passwd и прав $user_permit
2. ...

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


