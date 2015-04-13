# auth-dav
Nginx Base Authenticate url/.htpasswd for WebDAV and HTTP secure directory(links). Support CRYPT(3) MD5 SHA-1 secure hash. Test computation in Lua (5.1)

-- Copyright (c) 2015 by Yura Vdovytchenko
"https://ihome.itcod.com/max/project/auth-dav/",

Nginx Base Authenticate url/.htpasswd for WebDAV and HTTP secure directory(links)
Support CRYPT(3) MD5 SHA-1 secure hash.
Test computation in Lua (5.1)
Author by Yura Vdovytchenko (http://max.itcod.com)
License MIT

ОПИСАНИЕ
Модуль аутентификации для nginx. Nginx с поддержкой lua 5.1. 
Основная задача модуля обеспечить независимую парольную защиту для каждой папки на сайте (WEBDAV-хранилище/облака).
Реализовано методом автоматической Base-авторизации при обнаружении в папке/url файла авторизации (например: .htpasswd).
Поддерживает три базовых метода кодирования CRYPT(3) MD5 SHA1

ЗАМЕЧАНИЯ
На текущий момент WEBDAV-клиенты (BitKenix/FAR-NetDrive) обеспечивают только авторизацию при первичном входе и не умеют выдавать запрос 
авторизации при переходе в подпапку с иным авторизуемым пользователем.

REQUIRE
require "base64"
local utf8 = require "utf8" -- utf8.lua Kyle Smith https://gist.github.com/markandgo/5776124
local csv = require("csv") -- lua-csv https://github.com/geoffleyland/lua-csv
local resty_sha1 = require "resty.sha1" -- https://github.com/openresty/lua-resty-core
local apr = require "apr.core" -- lua-apr
-- Loading the library. crypt -- https://github.com/PlugwiseBV/luacrypt
descrypt = assert(package.loadlib("/usr/local/lib/lua/5.1/crypt.so", "luaopen_crypt"))

STARTUP
--path lua file: /etc/nginx/lua/auth-dav.lua
--Example Nginx virtual example.conf
local example = {
  _NGINX = [[
    server {
    ...
    set $dir /opt/home;
    set $dir_path $dir;
    set $home $dir_path;
    set $sadm_passwd .htpsw;
    set $user_passwd .uhtpasswd;

    location / {
	dav_methods PUT DELETE MKCOL COPY MOVE;
	dav_ext_methods PROPFIND OPTIONS;
	create_full_put_path on;
	dav_access user:rw group:rw;
	client_body_temp_path /opt/itcod-dav.tmp/;
	access_by_lua_file /etc/nginx/lua/auth-dav.lua;
	client_max_body_size 0;
	autoindex on;
        root /opt/home/;

        limit_except GET {
    	    allow all;
    	    #deny all;
        }
    }
    location ~/\.ht {
	deny all;
    }
  ]]
}
