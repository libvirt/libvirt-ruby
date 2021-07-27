# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool dockerfile centos-stream-8 libvirt+dist,libvirt-ruby
#
# https://gitlab.com/libvirt/libvirt-ci/-/commit/0bb9bfada8e143e05bb436a06747d227d19f0df4

FROM quay.io/centos/centos:stream8

RUN dnf update -y && \
    dnf install 'dnf-command(config-manager)' -y && \
    dnf config-manager --set-enabled -y powertools && \
    dnf install -y centos-release-advanced-virtualization && \
    dnf install -y epel-release && \
    dnf install -y \
        ca-certificates \
        ccache \
        gcc \
        git \
        glibc-devel \
        glibc-langpack-en \
        libvirt-devel \
        make \
        pkgconfig \
        rpm-build \
        ruby-devel \
        rubygem-rake \
        zip && \
    dnf autoremove -y && \
    dnf clean all -y && \
    rpm -qa | sort > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/gcc

ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"
