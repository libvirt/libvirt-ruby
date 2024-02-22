#!/bin/sh

set -e
set -v

rake clean || :

rake build
#rake test

rm -rf pkg
rake package

if [ -f /usr/bin/rpmbuild ]; then
    rake rpm
fi
