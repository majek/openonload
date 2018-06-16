######################################################################
# RPM spec file for OpenOnload
#
# Authors: See Changelog at bottom.
#
# To build a source RPM:
#   rpmbuild -ts openonload-ver.tgz
# OR:
#   cp openonload-ver.tgz $RPM/SOURCES
#   cp openonload-ver/scripts/onload_misc/openonload.spec $RPM/SPECS
#   rpmbuild -bs --define "_topdir $RPM" $RPM/SPECS/openonload.spec
#
# To build a binary RPM from source:
#   rpmbuild --rebuild --define "_topdir $RPM" $RPM/SRPMS/openonload-*.src.rpm
#
# If you want to build for kernel version which differs from the one in
# uname, use:
#   --define "kernel <full-kernel-name>"
#
# If you want to ensure that 32-bit lib will be built on 64-bit add:
#   --define "build32 true"
#
# If you want debug binary packages add:
#   --define "debug true"
#
# If your distribution does not provide a dist macro (e.g. CentOS) which is used
# to differentiate the filename, you may overrise it:
#    --define 'dist .el5'
#
# For PPC platform you can use IBM Advanced Toolchain. For this you should
#    --define 'ppc_at </opt cc path>
#
# If you want to specify a build profile add:
#    --define "build_profile <profile>"


%define pkgversion 201805

%{!?kernel:  %{expand: %%define kernel %%(uname -r)}}
%{!?target_cpu:  %{expand: %%define target_cpu %{_host_cpu}}}
%{!?kpath: %{expand: %%define kpath /lib/modules/%%{kernel}/build}}
%{!?build32: %{expand: %%define build32 false}}

%define knownvariants '@(BOOT|PAE|@(big|huge)mem|debug|enterprise|kdump|?(big|large)smp|uml|xen[0U]?(-PAE)|xen|rt?(-trace|-vanilla)|default|big|pae|vanilla|trace|timing)'
%define knownvariants2 '%{knownvariants}'?(_'%{knownvariants}')

# Assume that all non-suse distributions can be treated as redhat
%define redhat       %( [ "%{_vendor}" = "suse"   ] ; echo $?)

# Determine distro to use for package conflicts with SFC.  This is not
# accurate in various cases, and should be updated to use the sfc-disttag
# script that is used by the sfc spec file to generate their package name.
%define have_lsb %( ! which lsb_release > /dev/null 2>&1; echo $? )
%if %{have_lsb}
%define thisdist %(lsb_release -rs | cut -d. -f1)
%define maindist %{?for_rhel:%{for_rhel}}%{!?for_rhel:%{thisdist}}
%endif

%define kernel_installed %( [ -e "/lib/modules/%{kernel}" ] && rpm -q --whatprovides /lib/modules/%{kernel} > /dev/null && echo "1" || echo "0")

%if %kernel_installed

# kmodtool doesn't count 'rt' as a variant.  So I've stolen the bash
# regexp.  Only faffing with this because rpmbuild BuildRequires doesn't
# agree that kernel-rt provides 'kernel = blah-rt' !
# also some kernels have 2 parts in the variant
%define kvariantsuffix %(shopt -s extglob; KNOWNVARS='%{knownvariants2}'; KVER=%{kernel}; VAR=${KVER##${KVER%%%${KNOWNVARS}}}; [[ -n "$VAR" ]] && echo $VAR)
%define kvariantsuffix_dash %( KVAR='%{kvariantsuffix}'; [[ -n "${KVAR}" ]] && echo -"${KVAR}" || echo "")
%define kernel_cut   %(shopt -s extglob; KNOWNVARS='%{knownvariants2}'; KVER=%{kernel}; echo ${KVER%%%${KNOWNVARS}} | sed "s/-$//; s/_$//")
# some distros like to add architecture to the kernel name (Fedora)
%define kverrel        %(shopt -s extglob; KVER=%{kernel_cut}; echo ${KVER%%@(.i386|.i586|.i686|.x86_64|.ppc64)})

%else

# kernel for which you're trying to build is not installed on this particular host.
# We will assume that you provided us with a sensible name.

%define kvariantsuffix %(shopt -s extglob; KNOWNVARS='%{knownvariants2}'; KVER=%{kernel}; VAR=${KVER##${KVER%%%${KNOWNVARS}}}; [[ -n "$VAR" ]] && echo $VAR)
%define kvariantsuffix_dash %( KVAR='%{kvariantsuffix}'; [[ -n "${KVAR}" ]] && echo -"${KVAR}" || echo "")
%define kverrel %( echo %{kernel})

%endif  # kernel_installed

%define kpkgver %(echo '%{kverrel}' | sed 's/-/_/g')

%{echo: %{target_cpu}}

# Inhibit debuginfo package
%define debug_package %{nil}

###############################################################################

Summary     	: OpenOnload user-space
Name        	: openonload
Version     	: %(echo '%{pkgversion}' | sed 's/-/_/g')
Release     	: 1%{?dist}%{?debug:DEBUG}
Group       	: System Environment/Kernel
License   	: Various
URL             : http://www.openonload.org/
Vendor		: Solarflare Communications, Inc.
Provides	: openonload = %{version}-%{release}
Source0		: openonload-%{pkgversion}.tgz
BuildRoot   	: %{_builddir}/%{name}-root
AutoReqProv	: no
ExclusiveArch	: i386 i586 i686 x86_64 ppc64
BuildRequires	: gawk gcc sed make bash libpcap-devel python-devel automake libtool autoconf
# The glibc packages we need depend on distro and platform
%if %{redhat}
BuildRequires	: glibc-common 
%else
BuildRequires	: glibc-devel glibc
%ifarch x86_64
%if %{build32}
BuildRequires   : glibc-devel-32bit
%endif
%endif
%endif

%description
OpenOnload is a high performance user-level network stack.  Please see
www.openonload.org for more information.

This package comprises the user space components of OpenOnload.

###############################################################################
# Kernel version expands into NAME of RPM
%package kmod-%{kverrel}
Summary     	: OpenOnload kernel modules
Group       	: System Environment/Kernel
Requires	: openonload = %{version}-%{release}
Conflicts	: kernel-module-sfc-RHEL%{maindist}-%{kverrel}
Provides	: openonload-kmod = %{kpkgver}_%{version}-%{release}
Provides	: sfc-kmod-symvers = %{kernel}
AutoReqProv	: no

%description kmod-%{kverrel}
OpenOnload is a high performance user-level network stack.  Please see
www.openonload.org for more information.

This package comprises the kernel module components of OpenOnload.


###############################################################################
%prep
[ "$RPM_BUILD_ROOT" != / ] && rm -rf "$RPM_BUILD_ROOT"
%setup -n %{name}-%{pkgversion}

%build

# There are a huge variety of package names and formats for the various
# kernel and debug packages.  Trying to maintain correct BuildRequires has
# proven to be fragile, leading to repeated bugs as a new name format
# emerges.  Given that, we've given up, and just fail before build with a
# (hopefully) helfpul message if we can't find the headers that we need
# in the same way as the net driver spec file does.
[ -d "%{kpath}" ] || {
  set +x
  echo >&2 "ERROR: Kernel headers not found.  They should be at:"
  echo >&2 "ERROR:   %{kpath}"
%if %{redhat}
  echo >&2 "Hint: Install the $(echo '%{kernel}' | sed -r 's/(.*)(smp|hugemem|largesmp|PAE|xen)$/kernel-\2-devel-\1/; t; s/^/kernel-devel-/') package"
%else
  echo >&2 "Hint: Install the kernel-source-$(echo '%kernel}' | sed -r 's/-[^-]*$//') package"
%endif
  exit 1
}

export KPATH=%{kpath}
%ifarch x86_64 
./scripts/onload_build %{?build_profile:--build-profile %build_profile} \
  --kernelver "%{kernel}" %{?debug:--debug}
%else
%ifarch ppc64
# Don't try to build 32-bit userland on PPC
./scripts/onload_build %{?build_profile:--build-profile %build_profile} \
  --kernelver "%{kernel}" --kernel --user64 %{?debug:--debug} %{?ppc_at:--ppc-at %ppc_at}
%else
# Don't try to build 64-bit userland in case of 32-bit userland
./scripts/onload_build %{?build_profile:--build-profile %build_profile} \
  --kernelver "%{kernel}" --kernel --user32 %{?debug:--debug} %{?ppc_at:--ppc-at %ppc_at}
%endif
%endif

%install
export i_prefix=%{buildroot}
mkdir -p "$i_prefix/etc/modprobe.d"
mkdir -p "$i_prefix/etc/depmod.d"
./scripts/onload_install --verbose --kernelver "%{kernel}" \
  %{?build_profile:--build-profile %build_profile} \
  %{?debug:--debug} rpm_install
rm -f "%{buildroot}/etc/modprobe.conf"  # may be created by onload_install
docdir="$i_prefix%{_defaultdocdir}/%{name}-%{pkgversion}"
mkdir -p "$docdir"
install -m 644 LICENSE README* ChangeLog* ReleaseNotes* "$docdir"
install -D scripts/onload_install "%{buildroot}/lib/onload/onload_install"

%post
/lib/onload/onload_install rpm_post
ldconfig -n /usr/lib /usr/lib64

%preun
if [ -f /etc/modprobe.conf ]; then
  sed -i '/onload_start/,/onload_end/d' /etc/modprobe.conf
fi

if [ "$1" = 0 ]; then  # Erase, not upgrade
  if [ -x /usr/lib/lsb/remove_initd ]; then            \
    /usr/lib/lsb/remove_initd /etc/init.d/openonload;  \
  elif which chkconfig &>/dev/null; then               \
    chkconfig --del openonload;                        \
  elif which update-rc.d &>/dev/null; then             \
    update-rc.d -f openonload remove;                  \
  else                                                 \
    rm -f /etc/rc.d/rc*.d/*openonload;                 \
  fi
fi

%postun
ldconfig -n /usr/lib /usr/lib64

%post kmod-%{kverrel}
depmod -a "%{kernel}"

%postun kmod-%{kverrel}
depmod -a "%{kernel}"

%clean
rm -fR $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/lib*/lib*.so*
%attr(644, -, -) /usr/lib*/lib*.a
%ifarch x86_64
  /usr/lib*/zf
%endif
/usr/libexec/onload/apps
/usr/libexec/onload/profiles
%{_bindir}/*
%{_sbindir}/*
/lib/onload
/sbin/*
/usr/include/onload*
/usr/include/etherfabric/*.h
%ifarch x86_64
  /usr/include/zf*
%endif
%docdir %{_defaultdocdir}/%{name}-%{pkgversion}
%attr(644, -, -) %{_defaultdocdir}/%{name}-%{pkgversion}/*
%attr(644, -, -) %{_sysconfdir}/modprobe.d/onload.conf
%attr(644, -, -) %{_sysconfdir}/depmod.d/onload.conf
%config %attr(644, -, -) %{_sysconfdir}/sysconfig/openonload
%{_sysconfdir}/init.d/openonload
/usr/lib*/python*/site-packages/*

%files kmod-%{kverrel}
%defattr(744,root,root)
/lib/modules/%{kernel}/*/*

%changelog
* Thu Mar 5 2015 Kieran Mansley <kmansley@solarflare.com> 201502-u1
- Multiple updates to fix customer issues in spec file usage

* Mon May 14 2012 Mark Spender <mspender@solarflare.com> 201205
- Added fix for MRG trace and vanilla kernel variants

* Mon Feb 13 2012 Mark Spender <mspender@solarflare.com> 201202
- Added depenency fix for MRG rt kernels and RHEL 4 kernel variants  

* Thu Apr 28 2011 David Riddoch <driddoch@solarflare.com> 201104
- Added kernel module meta-data to help 3rd party modules.

* Wed Sep 22 2010 Konstantin Ushakov <kostik@oktetlabs.ru> 20100910
- SLES 9, 10, 10 work
- RHEL 4, 5 work
- Fedora 12 works

* Tue Jul 20 2010 David Riddoch <driddoch@solarflare.com> 20100604-u2
- Updates to reflect changes in 20100604 releases.
- Should support building a binary for kernel other than currently running.
- Various improvements.
- Works for me!

* Thu Apr 1 2010 Mike MacCana <mike.maccana@credit-suisse.com> 20100308-u1
- Fixed non-cronological changelog order
- Updated to new version
- Added 'extraversion' define as version cannot have dash in it

* Wed Oct 14 2009 David Riddoch <driddoch@solarflare.com> 20090901-1
- Substantial modifications to avoid redundancy by making onload_install
  cleverer

* Thu Aug 13 2009 Derek Whayman <Derek.Whayman@barclayscapital.com> 20090409-bc001
- Initial version

* Mon Jul 27 2009 Derek Whayman <Derek.Whayman@barclayscapital.com> 20090812-bc001
- New tarball from maintainer


