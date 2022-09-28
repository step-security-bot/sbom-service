%global __provides_exclude ^libjemalloc\\.so.*$
%global _hardened_build 1
%{!?with_tmpfiles_d: %global with_tmpfiles_d %{_sysconfdir}/tmpfiles.d}
%define who opensourceway
ExcludeArch:   i686
%global base_name1       antunit1

%global    base_name2       antunit2
%global base_name    beanutils
%global short_name   commons-%{base_name}


Name:          389-ds-base
Summary:       Base 389 Directory Server
Version:       1.4.3.20
Release:       1
License:       GPLv3+
Vendor:        %{who} himself
Packager:      opensourceways
AutoReqProv:   no
URL:           https://www.port389.org
Group:         Applications/Test
Source0:       https://releases.pagure.org/389-ds-base/389-ds-base-%{version}.tar.bz2
Source1:       389-ds-base-git.sh
Source2:       389-ds-base-devel.README
Source3:       https://github.com/jemalloc/jemalloc/releases/download/5.2.1/jemalloc-5.2.1.tar.bz2

Patch0:        CVE-2021-3652.patch
Patch1:        CVE-2021-3514.patch
# https://github.com/389ds/389-ds-base/commit/5a18aeb49c357a16c138d37a8251d73d8ed35319
Patch2:        Fix-attributeError-type-object-build_manpages.patch

BuildRequires: nspr-devel nss-devel >= 3.34 perl-generators openldap-devel libdb-devel cyrus-sasl-devel icu
BuildRequires: libicu-devel pcre-devel cracklib-devel gcc-c++ net-snmp-devel lm_sensors-devel bzip2-devel
BuildRequires: zlib-devel openssl-devel pam-devel systemd-units systemd-devel pkgconfig pkgconfig(systemd)
BuildRequires: pkgconfig(krb5) autoconf automake libtool doxygen libcmocka-devel libevent-devel chrpath
BuildRequires: python%{python3_pkgversion} python%{python3_pkgversion}-devel python%{python3_pkgversion}-setuptools
BuildRequires: python%{python3_pkgversion}-ldap python%{python3_pkgversion}-six python%{python3_pkgversion}-pyasn1
BuildRequires: python%{python3_pkgversion}-pyasn1-modules python%{python3_pkgversion}-dateutil
BuildRequires: python%{python3_pkgversion}-argcomplete python%{python3_pkgversion}-argparse-manpage
BuildRequires: python%{python3_pkgversion}-libselinux python%{python3_pkgversion}-policycoreutils
BuildRequires: python%{python3_pkgversion}-packaging rsync npm nodejs libtalloc-devel libtevent-devel
Requires:      389-ds-base-libs = %{version}-%{release}
Requires:      python%{python3_pkgversion}-lib389 = %{version}-%{release}
Requires:      policycoreutils-python-utils /usr/sbin/semanage libsemanage-python%{python3_pkgversion}
Requires:      selinux-policy >= 3.14.1-29 openldap-clients openssl-perl python%{python3_pkgversion}-ldap
Requires:      nss-tools nss >= 3.34 krb5-libs libevent cyrus-sasl-gssapi cyrus-sasl-md5 cyrus-sasl-plain
Requires:      libdb-utils
Requires:      perl-Errno >= 1.23-360 perl-DB_File perl-Archive-Tar cracklib-dicts
%{?systemd_requires}

Provides:      389-ds-base-libs = %{version}-%{release} svrcore = 4.1.4 ldif2ldbm >= 0
Obsoletes:     389-ds-base-libs < %{version}-%{release}
Obsoletes:     svrcore <= 4.1.3 389-ds-base <= 1.3.5.4 389-ds-base <= 1.4.0.9
Conflicts:     svrcore selinux-policy-base < 3.9.8 freeipa-server < 4.0.3

%description
389-ds-base is an LDAPv3 compliant server which includes
the LDAP server and command line utilities for server administration.

%package       legacy-tools
Summary:       Legacy utilities for 389 Directory Server
Obsoletes:     389-ds-base <= 1.4.0.9
Requires:      389-ds-base = %{version}-%{release} perl-Socket perl-NetAddr-IP
Requires:      perl-Mozilla-LDAP bind-utils
Requires:      perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
%global __provides_exclude_from %{_libdir}/dirsrv/perl
%global __requires_exclude perl\\((DSCreate|DSMigration|DSUpdate|DSUtil|Dialog|DialogManager|FileConn|Inf|Migration|Resource|Setup|SetupLog)
%{?perl_default_filter}

%description   legacy-tools
Legacy and deprecated utilities for 389 Directory Server.

%package       devel
Summary:       Development libraries for 389 Directory Server
Requires:      389-ds-base-libs = %{version}-%{release} pkgconfig nspr-devel nss-devel >= 3.34
Requires:      openldap-devel libtalloc libevent libtevent systemd-libs
Provides:      svrcore-devel = 4.1.4
Conflicts:     svrcore-devel
Obsoletes:     svrcore-devel <= 4.1.3

%description   devel
Development Libraries and headers for the 389 Directory Server.

%package       snmp
Summary:       SNMP Agent for 389 Directory Server
Requires:      389-ds-base = %{version}-%{release}
Obsoletes:     389-ds-base <= 1.4.0.0

%description   snmp
SNMP Agent for the 389 Directory Server.

%package       -n python%{python3_pkgversion}-lib389
Summary:       Library for accessing, testing, and configuring 389 Directory Server
BuildArch:     noarch
Requires:      krb5-workstation krb5-server openssl iproute python%{python3_pkgversion}
Requires:      python%{python3_pkgversion}-ldap python%{python3_pkgversion}-six
Requires:      python%{python3_pkgversion}-pyasn1 python%{python3_pkgversion}-pyasn1-modules
Requires:      python%{python3_pkgversion}-dateutil python%{python3_pkgversion}-argcomplete
Requires:      python%{python3_pkgversion}-libselinux
%{?python_provide:%python_provide python%{python3_pkgversion}-lib389}

%description   -n python%{python3_pkgversion}-lib389
Tools and libraries for accessing, testing, and configuring the 389 Directory Server.

%package       -n cockpit-389-ds
Summary:       Cockpit UI Plugin for configuring and administering 389 Directory Server
BuildArch:     noarch
Requires:      cockpit python%{python3_pkgversion} python%{python3_pkgversion}-lib389

%description   -n cockpit-389-ds
A cockpit UI Plugin for configuring and administering the 389 Directory Server

%package       help
Summary:       Documentation for 389 Directory Server
Requires:      389-ds-base = %{version}-%{release}

%description   help
Documentation for 389 Directory Server.

%prep
%autosetup -n 389-ds-base-%{version} -p1

%setup -n 389-ds-base-%{version} -T -D -b 3

cp %{SOURCE2} README.devel

%build

OPENLDAP_FLAG="--with-openldap"
%{?with_tmpfiles_d: TMPFILES_FLAG="--with-tmpfiles-d=%{with_tmpfiles_d}"}
NSSARGS="--with-nss-lib=%{_libdir} --with-nss-inc=%{_includedir}/nss3"

LEGACY_FLAGS="--enable-legacy --enable-perl"
cd ../jemalloc-5.2.1
%configure --libdir=%{_libdir}/dirsrv/lib --bindir=%{_libdir}/dirsrv/bin --enable-prof
%make_build
cd -

%define _strict_symbol_defs_build 1
autoreconf -fiv
%configure --enable-autobind --with-selinux $OPENLDAP_FLAG $TMPFILES_FLAG --with-systemd \
           --with-systemdsystemunitdir=%{_unitdir} \
           --with-systemdsystemconfdir=%{_sysconfdir}/systemd/system \
           --with-systemdgroupname=dirsrv.target --libexecdir=%{_libexecdir}/dirsrv \
           $NSSARGS $ASAN_FLAGS $RUST_FLAGS $PERL_FLAGS $CLANG_FLAGS $LEGACY_FLAGS --enable-cmocka --enable-perl

cd ./src/lib389
%py3_build
cd -
for f in "dsconf.8" "dsctl.8" "dsidm.8" "dscreate.8"; do
  sed -i  "1s/\"1\"/\"8\"/" %{_builddir}/389-ds-base-%{version}/src/lib389/man/$f
done
export XCFLAGS=$RPM_OPT_FLAGS
%make_build

%install
install -d %{buildroot}%{_datadir}/gdb/auto-load%{_sbindir}
install -d %{buildroot}%{_datadir}/cockpit
%make_install

find %{buildroot}%{_datadir}/cockpit/389-console -type d | sed -e "s@%{buildroot}@@" | sed -e 's/^/\%dir /' > cockpit.list
find %{buildroot}%{_datadir}/cockpit/389-console -type f | sed -e "s@%{buildroot}@@" >> cockpit.list
cp -r %{_builddir}/389-ds-base-%{version}/man/man3 $RPM_BUILD_ROOT/%{_mandir}/man3

cd src/lib389
%py3_install
cd -

for t in "log" "lib" "lock"; do
  install -d $RPM_BUILD_ROOT/var/$t/dirsrv
done

install -d $RPM_BUILD_ROOT%{_sysconfdir}/systemd/system/dirsrv.target.wants

%delete_la

sed -i -e 's|#{{PERL-EXEC}}|#!/usr/bin/perl|' $RPM_BUILD_ROOT%{_datadir}/dirsrv/script-templates/template-*.pl

cd ../jemalloc-5.2.1
make DESTDIR="$RPM_BUILD_ROOT" install_lib install_bin
cp -pa COPYING ../389-ds-base-%{version}/COPYING.jemalloc
cp -pa README ../389-ds-base-%{version}/README.jemalloc
cd -

cd  $RPM_BUILD_ROOT/usr
file `find -type f`| grep -w ELF | awk -F":" '{print $1}' | for i in `xargs`
do
  chrpath -d $i
done
cd -
mkdir -p  $RPM_BUILD_ROOT/etc/ld.so.conf.d
echo "%{_bindir}/%{name}" > $RPM_BUILD_ROOT/etc/ld.so.conf.d/%{name}-%{_arch}.conf
echo "%{_libdir}/%{name}" >> $RPM_BUILD_ROOT/etc/ld.so.conf.d/%{name}-%{_arch}.conf

%check
if ! make DESTDIR="$RPM_BUILD_ROOT" check; then
  cat ./test-suite.log && false;
fi

%post
/sbin/ldconfig
if [ -n "$DEBUGPOSTTRANS" ] ; then
    output=$DEBUGPOSTTRANS
    output2=${DEBUGPOSTTRANS}.upgrade
else
    output=/dev/null
    output2=/dev/null
fi

/bin/systemctl daemon-reload >$output 2>&1 || :

USERNAME="dirsrv"
ALLOCATED_UID=389
GROUPNAME="dirsrv"
ALLOCATED_GID=389
HOMEDIR="/usr/share/dirsrv"

getent group $GROUPNAME >/dev/null || /usr/sbin/groupadd -f -g $ALLOCATED_GID -r $GROUPNAME
if ! getent passwd $USERNAME >/dev/null ; then
    if ! getent passwd $ALLOCATED_UID >/dev/null ; then
      /usr/sbin/useradd -r -u $ALLOCATED_UID -g $GROUPNAME -d $HOMEDIR -s /sbin/nologin -c "user for 389-ds-base" $USERNAME
    else
      /usr/sbin/useradd -r -g $GROUPNAME -d $HOMEDIR -s /sbin/nologin -c "user for 389-ds-base" $USERNAME
    fi
fi

sysctl --system &> $output; true

%preun
if [ $1 -eq 0 ]; then
  rm -rf %{_sysconfdir}/systemd/system/dirsrv.target.wants/* > /dev/null 2>&1 || :
fi

%postun
/sbin/ldconfig
if [ $1 = 0 ]; then
  rm -rf /var/run/dirsrv
fi

%post          snmp
%systemd_post dirsrv-snmp.service

%preun         snmp
%systemd_preun dirsrv-snmp.service dirsrv.target

%postun        snmp
%systemd_postun_with_restart dirsrv-snmp.service

%post          legacy-tools
if [ -n "$DEBUGPOSTTRANS" ] ; then
    output=$DEBUGPOSTTRANS
    output2=${DEBUGPOSTTRANS}.upgrade
else
    output=/dev/null
    output2=/dev/null
fi

instances=""
ninst=0

echo looking for instances in %{_sysconfdir}/dirsrv > $output 2>&1 || :
instbase="%{_sysconfdir}/dirsrv"
for dir in $instbase/slapd-* ; do
    echo dir = $dir >> $output 2>&1 || :
    if [ ! -d "$dir" ] ; then continue ; fi
    case "$dir" in *.removed) continue ;; esac
    basename=`basename $dir`
    inst="dirsrv@`echo $basename | sed -e 's/slapd-//g'`"
    echo found instance $inst - getting status  >> $output 2>&1 || :
    if /bin/systemctl -q is-active $inst ; then
       echo instance $inst is running >> $output 2>&1 || :
       instances="$instances $inst"
    else
       echo instance $inst is not running >> $output 2>&1 || :
    fi
    ninst=`expr $ninst + 1`
done
if [ $ninst -eq 0 ] ; then
    echo no instances to upgrade >> $output 2>&1 || :
    exit 0
fi

echo shutting down all instances . . . >> $output 2>&1 || :
for inst in $instances ; do
    echo stopping instance $inst >> $output 2>&1 || :
    /bin/systemctl stop $inst >> $output 2>&1 || :
done
echo remove pid files . . . >> $output 2>&1 || :
/bin/rm -f /var/run/dirsrv*.pid /var/run/dirsrv*.startpid

echo upgrading instances . . . >> $output 2>&1 || :
DEBUGPOSTSETUPOPT=`/usr/bin/echo $DEBUGPOSTSETUP | /usr/bin/sed -e "s/[^d]//g"`
if [ -n "$DEBUGPOSTSETUPOPT" ] ; then
    %{_sbindir}/setup-ds.pl -$DEBUGPOSTSETUPOPT -u -s General.UpdateMode=offline >> $output 2>&1 || :
else
    %{_sbindir}/setup-ds.pl -u -s General.UpdateMode=offline >> $output 2>&1 || :
fi

for inst in $instances ; do
    echo restarting instance $inst >> $output 2>&1 || :
    /bin/systemctl start $inst >> $output 2>&1 || :
done

exit 0

%files
%doc LICENSE LICENSE.GPLv3+ LICENSE.openssl README.jemalloc
%license COPYING.jemalloc
%{_libdir}/libsvrcore.so.*
%{_libdir}/dirsrv/{libslapd.so.*,libns-dshttpd-*.so,libsds.so.*,libldaputil.so.*,librewriters.so*}
%{_libdir}/dirsrv/lib/libjemalloc.so.2
%dir %{_sysconfdir}/dirsrv
%dir %{_sysconfdir}/dirsrv/schema
%config(noreplace)%{_sysconfdir}/dirsrv/schema/*.ldif
%dir %{_sysconfdir}/dirsrv/config
%dir %{_sysconfdir}/systemd/system/dirsrv.target.wants
%config(noreplace)%{_sysconfdir}/dirsrv/config/{slapd-collations.conf,certmap.conf,template-initconfig}
%{_datadir}/dirsrv
%{_datadir}/gdb/auto-load/*
%{_unitdir}
%{_bindir}/{dbscan,ds-replcheck,ds-logpipe.py,ldclt,logconv.pl,pwdhash,readnsstate}
%{_sbindir}/ns-slapd
%{_libexecdir}/dirsrv/ds_systemd_ask_password_acl
%{_libdir}/dirsrv/python
%dir %{_libdir}/dirsrv/plugins
%{_libdir}/dirsrv/plugins/*.so
%{_prefix}/lib/sysctl.d/*
%dir %{_localstatedir}/lib/dirsrv
%dir %{_localstatedir}/log/dirsrv
%ghost %dir %{_localstatedir}/lock/dirsrv
%exclude %{_sbindir}/ldap-agent*
%exclude %{_unitdir}/dirsrv-snmp.service
%{_libdir}/dirsrv/lib/
%{_libdir}/dirsrv/bin/
%exclude %{_libdir}/dirsrv/bin/{jemalloc-config,jemalloc.sh}
%exclude %{_libdir}/dirsrv/lib/{libjemalloc.a,libjemalloc.so,libjemalloc_pic.a,pkgconfig}
%config(noreplace) /etc/ld.so.conf.d/*

%files         devel
%doc LICENSE LICENSE.GPLv3+ LICENSE.openssl
%{_includedir}/svrcore.h
%{_includedir}/dirsrv
%{_libdir}/libsvrcore.so
%{_libdir}/dirsrv/{libslapd.so,libns-dshttpd.so,libsds.so,libldaputil.so}
%{_libdir}/pkgconfig/{svrcore.pc,dirsrv.pc,libsds.pc}

%files         legacy-tools
%doc LICENSE LICENSE.GPLv3+ LICENSE.openssl README.devel
%{_bindir}/{infadd,ldif,migratecred,mmldif,rsearch,repl-monitor,cl-dump}
%config(noreplace)%{_sysconfdir}/dirsrv/config/template-initconfig
%{_sbindir}/{ldif2ldap,bak2db,db2bak,db2index,db2ldif,dbverify,ldif2db,restart-dirsrv}
%{_sbindir}/{start-dirsrv,status-dirsrv,stop-dirsrv,upgradedb,vlvindex}
%{_sbindir}/{monitor,dbmon.sh,dn2rdn,restoreconfig,saveconfig,suffix2instance,upgradednformat}
%{_libexecdir}/dirsrv/{ds_selinux_enabled,ds_selinux_port_query}
%{_datadir}/dirsrv/properties/*.res
%{_datadir}/dirsrv/script-templates
%{_datadir}/dirsrv/updates
%{_bindir}/{repl-monitor.pl,cl-dump.pl,dbgen.pl}
%{_sbindir}/*.pl
%{_libdir}/dirsrv/perl

%files         snmp
%doc LICENSE LICENSE.GPLv3+ LICENSE.openssl
%config(noreplace)%{_sysconfdir}/dirsrv/config/ldap-agent.conf
%{_sbindir}/ldap-agent*
%{_unitdir}/dirsrv-snmp.service

%files         -n python%{python3_pkgversion}-lib389
%doc LICENSE LICENSE.GPLv3+
%{python3_sitelib}/lib389*
%{_sbindir}/{dsconf,dscreate,dsctl,dsidm}
%{_libexecdir}/dirsrv/dscontainer

%files         -n cockpit-389-ds -f cockpit.list
%{_datarootdir}/metainfo/389-console/org.port389.cockpit_console.metainfo.xml

%files         help
%doc README.md README.devel README.jemalloc
%{_mandir}/*/*

%changelog
* Fri Aug 05 2022 wangkai <wangkai385@h-partners.com> - 1.4.3.20-1
- Update to 1.4.3.20 for fix CVE-2020-35518

* Tue Apr 19 2022 yaoxin <yaoxin30@h-partners.com> - 1.4.0.31-6
- Resolve compilation failures

* Wed Sep 22 2021 liwu<liwu13@huawei.com> - 1.4.0.31-5
- fix CVE-2021-3652 CVE-2021-3514

* Wed Sep 08 2021 chenchen <chen_aka_jan@163.com> - 1.4.0.31-4
- del rpath from some binaries and bin

* Mon Aug 2 2021 Haiwei Li <lihaiwei8@huawei.com> - 1.4.0.31-3
- Fix complication failed due to gcc upgrade

* Wed Apr 29 2020 lizhenhua <lizhenhua21@huawei.com> - 1.4.0.31-2
- Package init
