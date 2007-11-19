%{!?ruby_sitelib: %define ruby_sitelib %(ruby -rrbconfig -e "puts Config::CONFIG['sitelibdir']")}
%{!?ruby_sitearch: %define ruby_sitearch %(ruby -rrbconfig -e "puts Config::CONFIG['sitearchdir']")}

Name:           ruby-libvirt
Version:        @VERSION@
Release:        1%{?dist}
Summary:        Ruby bindings for libvirt
Group:          Development/Languages

License:        LGPL
URL:            http://libvirt.org/ruby/
Source0:        http://libvirt.org/ruby/downloads/ruby-libvirt-@VERSION@.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ruby ruby-devel rubygem(rake)
Requires:       ruby(abi) = 1.8
Requires:       libvirt-devel
Provides:       ruby(libvirt) = %{version}

%description
Ruby bindings for libvirt.

%prep
%setup -q


%build
export CFLAGS="$RPM_OPT_FLAGS"
rake build

%install
rm -rf $RPM_BUILD_ROOT
install -d -m0755 %{buildroot}%{ruby_sitelib}
install -d -m0755 %{buildroot}%{ruby_sitearch}
install -p -m0644 lib/libvirt.rb %{buildroot}%{ruby_sitelib}
install -p -m0644 ext/libvirt/_libvirt.so %{buildroot}%{ruby_sitearch}
 
%check
rake test

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc COPYING NEWS README
%{ruby_sitelib}/libvirt.rb
%{ruby_sitearch}/_libvirt.so


%changelog
* Mon Nov 19 2007 David Lutterkort <dlutter@redhat.com> - 0.0.1-1
- Initial specfile

