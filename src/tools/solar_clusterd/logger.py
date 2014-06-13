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
import time

class Logger(object):
    def __init__(self, *targets):
        self.start_of_line = True
        self.targets = list(targets)

    def fileno(self):
        if self.targets:
            return self.targets[0].fileno()
        return -1

    def flush(self):
        for target in self.targets:
            target.flush()

    def isatty(self):
        return False

    def write(self, text):
        header = time.asctime() + ': '
        if self.start_of_line:
            text = header + text
        self.start_of_line = text.endswith('\n')
        if self.start_of_line:
            text = text[:-1].replace('\n', '\n' + header) + '\n'
        else:
            text = text.replace('\n', '\n' + header)
        for target in self.targets:
            target.write(text)
            target.flush()
