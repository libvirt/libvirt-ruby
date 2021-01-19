# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool dockerfile opensuse-152 libvirt+dist,libvirt-ruby
#
# https://gitlab.com/libvirt/libvirt-ci/-/commit/740f5254f607de914a92d664196d045149edb45a
FROM registry.opensuse.org/opensuse/leap:15.2

RUN zypper update -y && \
    zypper install -y \
           ca-certificates \
           ccache \
           gcc \
           git \
           glibc-devel \
           glibc-locale \
           libvirt-devel \
           make \
           pkgconfig \
           rpm-build \
           ruby \
           ruby-devel \
           zip && \
    zypper clean --all && \
    rpm -qa | sort > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/$(basename /usr/bin/gcc)

ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"
