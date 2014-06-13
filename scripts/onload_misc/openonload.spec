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
# --define 'ppc_at </opt cc path>

# TODO:
# RHEL and SLES have their own smart systems of kernel packaging. They are
# under development and for sure are not in RHEL4 and SLES9.
# RHEL: http://www.kerneldrivers.org/RedHatKernelModulePackages
# SLES: CODE10
#
# kmodtool and sles specic spec macro can be used to generate a template for
# kernel modules packaging.  Perhaps it's reasonable (when we don't need to
# support older distros) to update this spec to use kernel modules packaging
# templates.

%define pkgversion 201310-u2

%{!?kernel:  %{expand: %%define kernel %%(uname -r)}}
%{!?target_cpu:  %{expand: %%define target_cpu %{_host_cpu}}}
%{!?kpath: %{expand: %%define kpath /lib/modules/%%{kernel}/build}}
%{!?build32: %{expand: %%define build32 false}}

%define have_lsb %( ! which lsb_release > /dev/null 2>&1; echo $? )

%define knownvariants '@(BOOT|PAE|@(big|huge)mem|debug|enterprise|kdump|?(big|large)smp|uml|xen[0U]?(-PAE)|xen|rt?(-trace|-vanilla)|default|big|pae|vanilla|trace|timing)'
%define knownvariants2 '%{knownvariants}'?(_'%{knownvariants}')

# Determine distro
%if %{have_lsb}
# '\' signs are not recognised by RedHat 4 rpm
%define redhat %(lsb_release -is | grep -qi -e redhat -e cent -e fedora -e oracle && echo 1; lsb_release -is | grep -qi suse && echo 0)

%define thisdist %(lsb_release -rs | cut -d. -f1)
# Do we really need this? Why?
%define maindist %{?for_rhel:%{for_rhel}}%{!?for_rhel:%{thisdist}}
%else
# old distros or strange installations
%define redhat %( ! [ -e /etc/redhat-release ]; echo $? )
%endif

%define kernel_installed %( [ -e "/lib/modules/%{kernel}" ] && rpm -q --whatprovides /lib/modules/%{kernel} > /dev/null && echo "1" || echo "0")

%if %kernel_installed

%define kernel_pkg %( rpm -q --whatprovides /lib/modules/%{kernel} | grep kernel | grep -v source | grep -v base) 
# form a fake kernel name in known format 2.6.32-0.41-rt
%define kernel_long %( echo %{kernel_pkg} | sed "s/kernel-\\([a-zA-Z_-]*\\)[-\.]\\([2-9].[0-9].*\\)/\\2-\\1/; s/kernel-//")

%else

# kernel for which you're trying to build is not installed on this particular host.
# we'll try to guess something and make some magic afterwards

# kmodtool is not present in RHEL 4
%define have_kmodtool %( ! [ -e /usr/lib/rpm/redhat/kmodtool ]; echo $? )

%if %{redhat} && %{have_kmodtool}
%define kmodtool sh /usr/lib/rpm/redhat/kmodtool
%define kernel_long %(%{kmodtool} verrel %{?kernel} 2>/dev/null | sed "s/-$//")
# Unfortunately kmodtool does not support some variant-suffix values
%else
# no kmodtool on SLES or old RHEL
%define kernel_long %{kernel}
%endif				# rhel

%endif				# magic

# Pre RHEL5 the headers are present in the same package
%if %{redhat} && %{have_lsb}
%define libpcap_devel %( [ %{thisdist} -ge 5 ] && echo libpcap-devel || echo libpcap )
%else
%define libpcap_devel libpcap-devel
%endif

# On SLES11 source packages for RT kernels are called kernel-source-rt
# rather than kernel-source.
%define rtkernel %( echo %{kernel} | grep -q -- -rt && echo 1 || echo 0 )
%if 0%{?sles_version} >= 11 && %{rtkernel}
%define kernelsource  kernel-source-rt
%else
%define kernelsource  kernel-source
%endif

# kmodtool doesn't count 'rt' as a variant.  So I've stolen the bash
# regexp.  Only faffing with this because rpmbuild BuildRequires doesn't
# agree that kernel-rt provides 'kernel = blah-rt' !
# also some kernels have 2 parts in the variant
%define kvariantsuffix %(shopt -s extglob; KNOWNVARS='%{knownvariants2}'; KVER=%{kernel_long}; VAR=${KVER##${KVER%%%${KNOWNVARS}}}; [[ -n "$VAR" ]] && echo $VAR)
%define kvariantsuffix_dash %( KVAR='%{kvariantsuffix}'; [[ -n "${KVAR}" ]] && echo -"${KVAR}" || echo "")
%define kernel_cut   %(shopt -s extglob; KNOWNVARS='%{knownvariants2}'; KVER=%{kernel_long}; echo ${KVER%%%${KNOWNVARS}} | sed "s/-$//; s/_$//")
# some distros like to add architecture to the kernel name (Fedora)
%define kverrel        %(shopt -s extglob; KVER=%{kernel_cut}; echo ${KVER%%@(.i386|.i586|.i686|.x86_64|.ppc64)})

%{echo: %{target_cpu}}

# do we need this?
%define debug_package %{nil}

###############################################################################

Summary     	: OpenOnload user-space
Name        	: openonload
Version     	: %(echo '%{pkgversion}' | sed 's/-/_/g')
Release     	: 1%{?dist}%{?debug:DEBUG}
Group       	: System Environment/Kernel
License   	: Various
URL             : http://www.openonload.org/
#Packager    	: Acme Widgets, Inc.
Vendor		: Solarflare Communications, Inc.
Provides	: openonload = %{version}-%{release}
Source0		: openonload-%{pkgversion}.tgz
BuildRoot   	: %{_builddir}/%{name}-root
AutoReqProv	: no
%if %{redhat}
BuildRequires	: gawk gcc sed make bash kernel%{kvariantsuffix_dash} = %{kverrel} kernel%{kvariantsuffix_dash}-devel = %{kverrel} glibc-common %{libpcap_devel} python-devel
%else
BuildRequires	: gawk gcc sed make bash kernel%{kvariantsuffix_dash} = %{kverrel} %{kernelsource} = %{kverrel} glibc-devel glibc %{libpcap_devel} python-devel
%ifarch x86_64
%if %{build32}
BuildRequires   : glibc-devel-32bit
%endif
%endif

%endif                          # else redhat
#BuildArch	: x86_64
ExclusiveArch	: i386 i586 i686 x86_64 ppc64

%description
OpenOnload is a high performance user-level network stack.  Please see
www.openonload.org for more information.

This package comprises the user space components of OpenOnload.

###############################################################################
# Kernel version expands into NAME of RPM
%package kmod-%{kverrel}
Summary     	: OpenOnload kernel modules
Group       	: System Environment/Kernel

%if %{redhat}

#RHEL5 PAE kernel dependencies only have PAE at the end of the kernel version
#RHEL4 hughemem and smp kernels and MRG kernels have dependencies with the variant included in the name (e.g. kernel-rt-x86_64 = ...)
%ifarch ppc64
Requires	: openonload = %{version}-%{release}, kernel%{kvariantsuffix_dash} = %{kverrel}
%else
%if %( ! echo %{kvariantsuffix} | grep PAE &> /dev/null; echo $? )
Requires	: openonload = %{version}-%{release}, kernel-%{target_cpu} = %{kverrel}%{kvariantsuffix}
%else
%if %( ! echo %{kvariantsuffix} | grep -E trace\|vanilla &> /dev/null; echo $? )
Requires	: openonload = %{version}-%{release}, kernel%{kvariantsuffix_dash} = %{kverrel}
%else
Requires	: openonload = %{version}-%{release}, kernel%{kvariantsuffix_dash}-%{target_cpu} = %{kverrel}
%endif
%endif
%endif

%else
Requires	: openonload = %{version}-%{release}, kernel%{kvariantsuffix_dash} = %{kverrel}
%endif
Conflicts	: kernel-module-sfc-RHEL%{maindist}-%{kverrel}
Provides	: openonload-kmod = %{kverrel}-%{version}-%{release}
AutoReqProv	: no

# %define kmod_name %{name}

%description kmod-%{kverrel}
OpenOnload is a high performance user-level network stack.  Please see
www.openonload.org for more information.

This package comprises the kernel module components of OpenOnload.

# http://www.kerneldrivers.org/RedHatKernelModulePackages
# NOTE: these two extra defines will not be necessary in future.
# %define kmp_version %{version}
# %define kmp_release %{release}

###############################################################################
%prep
[ "$RPM_BUILD_ROOT" != / ] && rm -rf "$RPM_BUILD_ROOT"
%setup -n %{name}-%{pkgversion}

%build
export KPATH=%{kpath}
%ifarch x86_64 
./scripts/onload_build --kernelver "%{kernel}" %{?debug:--debug}
%else
%ifarch ppc64
# Don't try to build 32-bit userland on PPC
./scripts/onload_build --kernelver "%{kernel}" --kernel --user64 %{?debug:--debug} %{?ppc_at:--ppc-at %ppc_at}
%else
# Don't try to build 64-bit userland in case of 32-bit userland
./scripts/onload_build --kernelver "%{kernel}" --kernel --user32 %{?debug:--debug} %{?ppc_at:--ppc-at %ppc_at}
%endif
%endif

%install
export i_prefix=%{buildroot}
mkdir -p "$i_prefix/etc/modprobe.d"
mkdir -p "$i_prefix/etc/depmod.d"
./scripts/onload_install --verbose --kernelver "%{kernel}" \
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
for k in $(cd /lib/modules && /bin/ls); do
  [ -d "/lib/modules/$k/kernel/" ] && depmod -a "$k"
done
if [ -x "/sbin/weak-modules" ]; then
  for m in sfc sfc_tune sfc_resource sfc_char onload sfc_affinity; do
    echo "/lib/modules/%{kernel}/extra/$m.ko"
  done | /sbin/weak-modules --add-modules
fi

%postun kmod-%{kverrel}
for k in $(cd /lib/modules && /bin/ls); do
  [ -d "/lib/modules/$k/kernel/" ] && depmod -a "$k"
done
if [ "$1" = 0 ]; then  # Erase, not upgrade
  if [ -x "/sbin/weak-modules" ]; then
    for m in sfc sfc_tune sfc_resource sfc_char onload sfc_affinity; do
      echo "/lib/modules/%{kernel}/extra/$m.ko"
    done | /sbin/weak-modules --remove-modules
  fi
fi

%clean
rm -fR $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/lib*/lib*.so*
%attr(644, -, -) /usr/lib*/lib*.a
/usr/libexec/onload/apps
/usr/libexec/onload/profiles
%{_bindir}
%{_sbindir}
/lib/onload
/sbin
/usr/include/onload*
%docdir %{_defaultdocdir}/%{name}-%{pkgversion}
%attr(644, -, -) %{_defaultdocdir}/%{name}-%{pkgversion}/*
%attr(644, -, -) %{_sysconfdir}/modprobe.d/onload.conf
%attr(644, -, -) %{_sysconfdir}/modprobe.d/sfc_aoe.conf
%attr(644, -, -) %{_sysconfdir}/depmod.d/onload.conf
%config %attr(644, -, -) %{_sysconfdir}/sysconfig/openonload
%{_sysconfdir}/init.d/openonload
/usr/lib*/python*

%files kmod-%{kverrel}
%defattr(744,root,root)
/lib/modules/%{kernel}/*/*
/usr/libexec/onload/modules

%changelog
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

* Tue Jul 27 2009 Derek Whayman <Derek.Whayman@barclayscapital.com> 20090812-bc001
- New tarball from maintainer


