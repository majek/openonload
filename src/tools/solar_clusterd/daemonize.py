#****************************************************************************
# Copyright (c) 2013, Solarflare Communications Inc,
#
# Maintained by Solarflare Communications
#  <onload-dev@solarflare.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation, incorporated herein by reference.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#****************************************************************************
import os, sys, pwd, grp


def check_pidfile(pidfile):
    if os.path.isfile(pidfile):
        o = file(pidfile, 'r')
        text = o.read().strip()
        o.close()
        if text.isdigit():
            pid = int(text)
            sys.stderr.write("Found existing pidfile %s containing %d\n" % (
                    pidfile, pid))
            if os.path.isdir(os.path.join('/proc/', str(pid))):
                raise Exception("Daemon already running as PID %d" % pid)
            else:
                sys.stdout.write("PID %d has died; removing state pidfile\n" %
                                 pid)
                os.unlink(pidfile)
        else:
            os.unlink(pidfile) # unreadable pidfile


def _do_user(user, group):
    if group:
        os.setgid( grp.getgrnam(group).gr_gid )
        os.setuid( pwd.getpwnam(user).pw_uid )
    else:
        x = pwd.getpwnam(user)
        os.setgid(x.pw_gid)
        os.setuid(x.pw_uid)


def _do_fork(pidfile):
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.chdir('/')
    os.setsid()
    os.umask(002)

    pid = os.fork()
    if pid > 0:
        open(pidfile, 'w').write('%d\n'%pid)
        sys.exit(0)

    sys.stdout.write("Running as a daemon, pid %d" % os.getpid())


def daemonize(procname, pidfile, user=None, group=None):
    # TODO: Set the process name to something more helpful than
    # 'python'

    _do_fork(pidfile)

    if user:
        _do_user(user, group)

    null_fd = os.open('/dev/null', os.O_RDWR)
    for fd in range(3):
        os.dup2(null_fd, fd)
