# -*- ruby -*-
# Rakefile: build ruby libvirt bindings
#
# Copyright (C) 2007 Red Hat, Inc.
#
# Distributed under the GNU Lesser General Public License v2.1 or later.
# See COPYING for details
#
# David Lutterkort <dlutter@redhat.com>

# Rakefile for ruby-rpm -*- ruby -*-
require 'rake/clean'
require 'rake/rdoctask'
require 'rake/testtask'
require 'rake/gempackagetask'

PKG_NAME='ruby-libvirt'
PKG_VERSION='0.1.0'

EXT_CONF='ext/libvirt/extconf.rb'
MAKEFILE="ext/libvirt/Makefile"
LIBVIRT_MODULE="ext/libvirt/_libvirt.so"
SPEC_FILE="ruby-libvirt.spec"
LIBVIRT_SRC=LIBVIRT_MODULE.gsub(/.so$/, ".c")

#
# Additional files for clean/clobber
#

CLEAN.include [ "ext/**/*.o", LIBVIRT_MODULE,
                "ext/**/depend" ]

CLOBBER.include [ "config.save", "ext/**/mkmf.log",
                  MAKEFILE ]

#
# Build locally
#
# FIXME: We can't get rid of install.rb yet, since there's no way
# to pass config options to extconf.rb
file MAKEFILE => EXT_CONF do |t|
    Dir::chdir(File::dirname(EXT_CONF)) do
         unless sh "ruby #{File::basename(EXT_CONF)}"
             $stderr.puts "Failed to run extconf"
             break
         end
    end
end
file LIBVIRT_MODULE => [ MAKEFILE, LIBVIRT_SRC ] do |t|
    Dir::chdir(File::dirname(EXT_CONF)) do
         unless sh "make"
             $stderr.puts "make failed"
             break
         end
     end
end
desc "Build the native library"
task :build => LIBVIRT_MODULE

Rake::TestTask.new(:test) do |t|
    t.test_files = FileList['tests/tc_*.rb']
    t.libs = [ 'lib', 'ext/libvirt' ]
end
task :test => :build

Rake::RDocTask.new do |rd|
    rd.main = "README.rdoc"
    rd.rdoc_dir = "doc/site/api"
    rd.rdoc_files.include("README.rdoc", "lib/**/*.rb", "ext/**/*.[ch]")
end

#
# Package tasks
#

PKG_FILES = FileList[
  "Rakefile", "COPYING", "README", "NEWS", "README.rdoc",
  "lib/**/*.rb",
  "ext/**/*.[ch]", "ext/**/MANIFEST", "ext/**/extconf.rb",
  "tests/**/*",
  "spec/**/*"
]

DIST_FILES = FileList[
  "pkg/*.src.rpm",  "pkg/*.gem",  "pkg/*.zip", "pkg/*.tgz"
]

SPEC = Gem::Specification.new do |s|
    s.name = PKG_NAME
    s.version = PKG_VERSION
    s.email = "libvir-list@redhat.com"
    s.homepage = "http://libvirt.org/ruby/"
    s.summary = "Ruby bindings for LIBVIRT"
    s.files = PKG_FILES
    s.autorequire = "libvirt"
    s.required_ruby_version = '>= 1.8.1'
    s.extensions = "ext/libvirt/extconf.rb"
    s.description = <<EOF
Provides bindings for libvirt.
EOF
end

Rake::GemPackageTask.new(SPEC) do |pkg|
    pkg.need_tar = true
    pkg.need_zip = true
end

desc "Update the ruby-libvirt site"
task :site => [ :rdoc ] do |t|
    system("rsync -av doc/site/ libvirt:/data/www/libvirt.org/ruby/")
    if $? != 0
        raise "rsync failed: #{$?}"
    end
end

desc "Build (S)RPM for #{PKG_NAME}"
task :rpm => [ :package ] do |t|
    system("sed -e 's/@VERSION@/#{PKG_VERSION}/' #{SPEC_FILE} > pkg/#{SPEC_FILE}")
    Dir::chdir("pkg") do |dir|
        dir = File::expand_path(".")
        system("rpmbuild --define '_topdir #{dir}' --define '_sourcedir #{dir}' --define '_srcrpmdir #{dir}' --define '_rpmdir #{dir}' --define '_builddir #{dir}' -ba #{SPEC_FILE} > rpmbuild.log 2>&1")
        if $? != 0
            raise "rpmbuild failed"
        end
    end
end

desc "Release a version to the site"
task :dist => [ :rpm ] do |t|
    puts "Copying files"
    unless sh "scp -p #{DIST_FILES.to_s} libvirt:/data/www/libvirt.org/ruby/download"
        $stderr.puts "Copy to libvirt failed"
        break
    end
    puts "Commit and tag #{PKG_VERSION}"
    system "hg commit -m 'Released version #{PKG_VERSION}'"
    system "hg tag -m 'Tag release #{PKG_VERSION}' #{PKG_NAME}-#{PKG_VERSION}"
end
