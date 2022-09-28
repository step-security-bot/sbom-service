%{!?python_path:%global python_path %(%{__python3} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

%{!?delete_la:%global delete_la find $RPM_BUILD_ROOT -type f -name "*.la" -delete}

%global python_pak_name python3-%{name}

Name:          volume_key
Version:       0.3.12
Release:       3
Summary:       A library used in case of volume key forgetting, and other associated tools.
License:       GPLv2 and (MPLv1.1 or GPLv2)
URL:           https://pagure.io/volume_key
Source0:       https://releases.pagure.org/volume_key/%{name}-%{version}.tar.xz

BuildRequires: cryptsetup-luks-devel gettext-devel glib2-devel gnupg2 gpgme-devel libblkid-devel nss-devel python3-devel nss-tools
BuildRequires: gcc
Requires:      gnupg2 nss nss-util nspr
Provides:      %{name}-libs
Obsoletes:     %{name}-libs

%description
The volume_key project provides a libvolume_key, a library for manipulating
storage volume encryption keys and storing them separately from volumes, and an
associated command-line tool, named volume_key.

The main goal of the software is to allow restoring access to an encrypted
hard drive if the primary user forgets the passphrase.  The encryption key
back up can also be useful for extracting data after a hardware or software
failure that corrupts the header of the encrypted volume, or to access the
company data after an employee leaves abruptly.

In a corporate setting the IT help desk could use it to back up the encryption
keys before handing the computer over to the end user.  volume_key can be used
by individual users as well.

volume_key currently supports only the LUKS volume encryption format.  Support
for other formats is possible, some formats are planned for future releases.

The project's home page is at https://pagure.io/volume_key .

%package devel
Summary: A package for %{name} developers and other users with special development needs
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
This package includes header files and some dynamic link libfiles. It is basically useful for
%{name} developers.

%package help
Summary: Help package for %{name} including some man, info or readme files not concerning copyright informations

%description help
This package includes some readme, news files..etc. Files not concerning copyright informations.

%package -n %{python_pak_name}
Summary: Python3 bindings for %{name}
Requires: %{name}%{?_isa} = %{version}-%{release}

%description -n %{python_pak_name}
This package provides python3 bindings for %{name}. See description of %{name} package for more information.

%prep
%autosetup -n %{name}-%{version} -p1

%build
%configure --with-python=no --with-python3=yes
%make_build

%install
%make_install
%find_lang %{name}
%delete_la

%check
make check

%post
ldconfig

%postun
ldconfig

%files -f %{name}.lang
%doc AUTHORS COPYING
%{_bindir}/%{name}
%{_libdir}/lib%{name}.so.*

%files devel
%{_includedir}/%{name}
%{_libdir}/lib%{name}.so

%files help
%doc README contrib NEWS ChangeLog
%{_mandir}/man8/%{name}.8*

%files -n %{python_pak_name}
%{python_path}/_%{name}.so
%{python_path}/%{name}.py*
%{python_path}/__pycache__/%{name}.*

%changelog
* Fri May 28 2021 yangzhuangzhuang<yangzhuangzhuang1@huawei.com> - 0.3.12-3
- The "no acceptable C compiler found" error message is displayed during compilation.Therefore,add buildrequires gcc.

* Tue Sep 10 2019 huzhiyu<huzhiyu1@huawei.com> - 0.3.12-2
- Package init