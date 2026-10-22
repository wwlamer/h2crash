#!/bin/sh
set -e
version=${1:-2.4.68}
port=${2:-8107}
here=$(cd "$(dirname "$0")" && pwd)
work="$here/build-$version"
mkdir -p "$work" "$here/run" "$here/root-$version"
cd "$work"
curl -fsSLO "https://archive.apache.org/dist/httpd/httpd-$version.tar.gz"
curl -fsSL -o apr.tar.gz https://archive.apache.org/dist/apr/apr-1.7.6.tar.gz
curl -fsSL -o apr-util.tar.gz https://archive.apache.org/dist/apr/apr-util-1.6.3.tar.gz
tar xzf "httpd-$version.tar.gz"
tar xzf apr.tar.gz
tar xzf apr-util.tar.gz
mv apr-1.7.6 "httpd-$version/srclib/apr"
mv apr-util-1.6.3 "httpd-$version/srclib/apr-util"
cd "httpd-$version"
./configure --prefix="$here/install-$version" --enable-http2 --with-included-apr --enable-mods-shared=most --disable-ssl
make -j"$(nproc)"
make install
sed -e "s|@ROOT@|$here|g" -e "s|@INSTALL@|$here/install-$version|g" -e "s|@PORT@|$port|g" -e "s|@VERSION@|$version|g" "$here/httpd.conf" > "$here/httpd-$version.conf"
printf 'ok' > "$here/root-$version/index.html"
echo "готово: $here/httpd-$version.conf"
