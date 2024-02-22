# -*- ruby -*-
# Rakefile: build ruby libvirt bindings
#
# Copyright (C) 2007,2010 Red Hat, Inc.
# Copyright (C) 2013,2014 Chris Lalancette <clalancette@gmail.com>
#
# Distributed under the GNU Lesser General Public License v2.1 or later.
# See COPYING for details
#
# David Lutterkort <dlutter@redhat.com>

# Rakefile for ruby-rpm -*- ruby -*-
require 'rake/clean'
require 'rake/testtask'
require 'rdoc/task'
require 'rubygems/package_task'

PKG_NAME='ruby-libvirt'
PKG_VERSION='0.8.2'

EXT_CONF='ext/libvirt/extconf.rb'
MAKEFILE="ext/libvirt/Makefile"
LIBVIRT_MODULE="ext/libvirt/_libvirt.so"
SPEC_FILE="ruby-libvirt.spec"
LIBVIRT_SRC=Dir.glob("ext/libvirt/*.c")
LIBVIRT_SRC << MAKEFILE

#
# Additional files for clean/clobber
#

CLEAN.include [ "ext/**/*.o", LIBVIRT_MODULE ]

CLOBBER.include [ "ext/**/mkmf.log", "ext/**/extconf.h", MAKEFILE ]

task :default => :build

#
# Build locally
#
file MAKEFILE => EXT_CONF do |t|
    Dir::chdir(File::dirname(EXT_CONF)) do
        sh "ruby #{File::basename(EXT_CONF)}"
    end
end
file LIBVIRT_MODULE => LIBVIRT_SRC do |t|
    Dir::chdir(File::dirname(EXT_CONF)) do
        sh "make"
    end
end
desc "Build the native library"
task :build => LIBVIRT_MODULE

#
# Test task
#

Rake::TestTask.new(:test) do |t|
    t.test_files = [ 'tests/test_conn.rb', 'tests/test_domain.rb',
                     'tests/test_interface.rb', 'tests/test_network.rb',
                     'tests/test_nodedevice.rb', 'tests/test_nwfilter.rb',
                     'tests/test_open.rb', 'tests/test_secret.rb',
                     'tests/test_storage.rb', 'tests/test_stream.rb' ]
    t.libs = [ 'lib', 'ext/libvirt' ]
end
task :test => :build

#
# Documentation tasks
#

RDOC_FILES = FileList[ "README.rdoc", "lib/libvirt.rb",
                       "ext/libvirt/_libvirt.c", "ext/libvirt/connect.c",
                       "ext/libvirt/domain.c", "ext/libvirt/interface.c",
                       "ext/libvirt/network.c", "ext/libvirt/nodedevice.c",
                       "ext/libvirt/nwfilter.c", "ext/libvirt/secret.c",
                       "ext/libvirt/storage.c", "ext/libvirt/stream.c" ]

RDoc::Task.new do |rd|
    rd.main = "README.rdoc"
    rd.rdoc_dir = "doc/site/api"
    rd.rdoc_files.include(RDOC_FILES)
end

RDoc::Task.new(:ri) do |rd|
    rd.main = "README.rdoc"
    rd.rdoc_dir = "doc/ri"
    rd.options << "--ri-system"
    rd.rdoc_files.include(RDOC_FILES)
end

#
# Package tasks
#

PKG_FILES = FileList[ "Rakefile", "COPYING", "README", "NEWS", "README.rdoc",
                      "lib/**/*.rb",
                      "ext/**/*.[ch]", "ext/**/extconf.rb",
                      "tests/**/*" ]

SPEC = Gem::Specification.new do |s|
    s.name = PKG_NAME
    s.version = PKG_VERSION
    s.email = "libvir-list@redhat.com"
    s.homepage = "https://ruby.libvirt.org/"
    s.summary = "Ruby bindings for LIBVIRT"
    s.files = PKG_FILES
    s.required_ruby_version = '>= 1.8.1'
    s.extensions = "ext/libvirt/extconf.rb"
    s.author = "David Lutterkort, Chris Lalancette"
    s.rubyforge_project = "None"
    s.description = "Ruby bindings for libvirt."
    s.license = "LGPL-2.1-or-later"
end

Gem::PackageTask.new(SPEC) do |pkg|
    pkg.need_tar = true
    pkg.need_zip = true
end

desc "Build (S)RPM for #{PKG_NAME}"
task :rpm => [ :package ] do |t|
    pkg_dir = File::expand_path("pkg")
    sed = [
        "sed",
        "-e", "'s/@VERSION@/#{PKG_VERSION}/'",
        "#{SPEC_FILE}.in", ">#{pkg_dir}/#{SPEC_FILE}",
    ]
    sh sed.join(" ")
    rpmbuild = [
        "rpmbuild",
        "--clean",
        "--define", "'_topdir #{pkg_dir}'",
        "--define", "'_sourcedir #{pkg_dir}'",
        "--define", "'_srcrpmdir #{pkg_dir}'",
        "--define", "'_rpmdir #{pkg_dir}'",
        "--define", "'_builddir #{pkg_dir}'",
        "-ba", "#{pkg_dir}/#{SPEC_FILE}",
    ]
    sh rpmbuild.join(" ")
end
