#!/bin/sh

set -e
set -v

rake clean || :

rake build
#rake test

rm -rf pkg
rake package

if [ -f /usr/bin/rpmbuild ]; then
  ver=`grep '^PKG_VERSION' Rakefile | sed -e "s/PKG_VERSION=//" -e "s/'//g"`
  sed -e "s/\@VERSION\@/$ver/" < ruby-libvirt.spec > pkg/ruby-libvirt.spec
  rpmbuild --nodeps \
     --define "_sourcedir `pwd`/pkg" \
     -ba --clean pkg/ruby-libvirt.spec
fi
