# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool manifest ci/manifest.yml
#
# https://gitlab.com/libvirt/libvirt-ci

function install_buildenv() {
    dnf --quiet update -y
    dnf --quiet install 'dnf-command(config-manager)' -y
    dnf --quiet config-manager --set-enabled -y crb
    dnf --quiet install -y epel-release
    dnf --quiet install almalinux-release-devel -y
    dnf --quiet config-manager --set-enabled -y devel
    dnf --quiet install -y \
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
                zip
    rpm -qa | sort > /packages.txt
    mkdir -p /usr/libexec/ccache-wrappers
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/gcc
}

export CCACHE_WRAPPERSDIR="/usr/libexec/ccache-wrappers"
export LANG="en_US.UTF-8"
export MAKE="/usr/bin/make"
