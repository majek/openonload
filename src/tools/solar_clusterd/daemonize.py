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

import os, sys, pwd, grp, errno
import fcntl
import resource
import signal
import atexit
import logging
from logging import handlers

def daemonize(directory, user=None, group=None, verbose=False):
    pid = os.fork()
    if pid < 0:
        sys.stderr.write("Fork failed")
        sys.exit(1)
    if pid != 0:
        sys.exit(0)

    pid = os.setsid()
    if pid == -1:
        sys.stderr.write("setsid failed")
        sys.exit(1)

    syslog = handlers.SysLogHandler('/dev/log')
    if verbose:
        syslog.setLevel(logging.DEBUG)
    else:
        syslog.setLevel(logging.INFO)
    # Try to mimic to normal syslog messages.
    formatter = logging.Formatter("%(asctime)s %(name)s: %(message)s",
                                  "%b %e %H:%M:%S")
    syslog.setFormatter(formatter)
    logger = logging.getLogger('solar_clusterd')
    logger.addHandler(syslog)

    # This is the same as 027.  There is no compatible way to specify
    # octals between 2.4, 2.6, 3.x so specifying in decimal.
    os.umask(23)
    os.chdir("/")

    if group:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            sys.stderr.write("Group {0} not found".format(group))
            sys.exit(1)
        try:
            os.setgid(gid)
        except OSError:
            sys.stderr.write("Unable to change gid.")
            sys.exit(1)
    if user:
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            sys.stderr.write("User {0} not found.".format(user))
            sys.exit(1)
        try:
            os.setuid(uid)
        except OSError:
            sys.stderr.write("Unable to change uid.")
            sys.exit(1)

    if os.path.exists(directory):
        sys.stderr.write('ERROR: directory %s already exists.  Either '
                         'another instance running or previous instance '
                         'did not clean up properly.  If no other '
                         'instance is running, please manually remove the '
                         'directory\n' % directory)
        sys.exit(1)
    os.makedirs(directory)

    os.close(0)
    os.close(1)
    os.close(2)
    os.open('/dev/null', os.O_RDWR)
    os.dup(0)
    os.dup(0)

    logger.warn("Starting daemon.")
    return logger
