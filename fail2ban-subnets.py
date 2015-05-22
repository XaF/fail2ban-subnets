#!/usr/bin/env python
# encoding: utf-8
#
# fail2ban-subnets, ban subnets from which IP are repeat offenders
#
# Copyright (C) 2015        Raphaël Beamonte <raphael.beamonte@gmail.com>
#
# This file is part of TraktForVLC.  TraktForVLC is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
# or see <http://www.gnu.org/licenses/>.

from datetime import datetime
import glob
import gzip
import logging
import os.path
import re
import subprocess
import time

# Path of logfile to analyze (accepts jokers)
filepath = '/var/log/fail2ban.log*'

# Maximum time to look back for our analyze
findtime = 4 * 4 * 7 * 86400

# Maximum number of bans in the period before reporting the range
maxretry = 50

# Minimum number of ips in the incriminated range
min_ips = 5

# Time format used in fail2ban logs
timeformat = '%Y-%m-%d %H:%M:%S,%f'

# Whether or not to exclude from report already banned subnets.
# This prevents the 'already banned' messages in fail2ban logs,
# it could however let a delay before banning again those ranges
# after restarting fail2ban. A larger findtime option in the subnets
# jail is recommanded when this option is activated.
excludeban = True

# Jail used in fail2ban for this script
subnetsjail = 'subnets'

# List of jails we don't want to match (for instance if you use recidive)
donotmatchjail = [
    'recidive',
]

# Fail regex to use to check if a line matches. Variables %(time)s
# and %(donotmatchjail)s can be used to insert previously mentionned
# parameters.
failregex = ('%(time)s fail2ban\.actions:(?: [A-Z]+)? ' +
             '\[(?!%(donotmatchjail)s\])(?P<JAIL>.*)\] ' +
             'Ban (?P<HOST>(?:[0-9]{1,3}\.){3}[0-9]{1,3})$')

# Where to store this scripts' logfile
logfile = '/var/log/fail2ban-subnets.log'

######
###### END OF CONFIGURATION
######

## Version
__version_info__ = (0, 2, 0, '', 0)
__version__ = "%d.%d.%d%s" % __version_info__[:4]

## Initialize logging
logging.basicConfig(
    format="%(asctime)s %(name)s: %(levelname)s %(message)s",
    level=logging.INFO,
    filename=logfile)

logger = logging.getLogger(os.path.basename(__file__))


# To humanize time
def human_readable_time(secs):
    mins, secs = divmod(secs, 60)
    hours, mins = divmod(mins, 60)
    days, hours = divmod(hours, 24)
    weeks, days = divmod(days, 7)

    readable = []
    for t, s in (
        (weeks, 'weeks'),
        (days,  'days'),
        (hours, 'hours'),
        (mins,  'mins'),
        (secs,  'secs'),
    ):
        if t:
            readable.append('%d %s' % (t, s))

    return ' '.join(readable)

logger.info("started with an analysis over %s" % human_readable_time(findtime))


# Function to log the subnets to ban
def logban(ipsubnet):
    data = {
        'ban':      ipsubnet['ban'],
        'subnet':   '%s/%s' % ipsubnet['subnet'],
        'ipn':      ipsubnet['ipn'],
        'iplist':   ipsubnet['iplist'],
    }

    logger.warning("subnet %(subnet)s has been banned "
                   "%(ban)d times with %(ipn)d ips" % data)


## TIME REGEX PREPARATION
timereplace = {
    '%Y':   '[0-9]{4}',
    '%m':   '(?:0?[0-9]|1[0-2])',
    '%d':   '(?:[0-2]?[0-9]|3[0-1])',
    '%H':   '(?:[0-1]?[0-9]|2[0-3])',
    '%M':   '(?:[0-5]?[0-9])',
    '%S':   '(?:[0-5]?[0-9])',
    '%f':   '[0-9]{3}',
}
timeregex_txt = '(?P<TIME>%s)' % timeformat
for k, v in timereplace.items():
    timeregex_txt = timeregex_txt.replace(k, v)
timeregex = re.compile(timeregex_txt)

## BAN REGEX PREPARATION
# Add the subnets jail to the jails not to match
donotmatchjail += [subnetsjail, ]
lineregex_txt = failregex % {
    'time': timeregex_txt,
    'donotmatchjail': ('(?:%s)' %
                       '|'.join([re.escape(j) for j in donotmatchjail]))
}
lineregex = re.compile(lineregex_txt)

## MINIMUM DATE TO CONSIDER ENTRIES
mintime = time.time() - findtime

## DICTIONNARY TO STORE RESULTS
# In an IP block, we'll store as key the
# block, and as value a value indicating
# the number of ban in this block and the
# list of ips matching
ipblocks = {}


## Convert an IP to int
def ip_to_int(a, b, c, d):
    return (a << 24) + (b << 16) + (c << 8) + d


## Calculate the subnet to use
def get_subnet(iplist):
    splittedlist = []
    for ip in iplist:
        splittedlist.append([int(chk) for chk in ip.split('.')])

    # Get max and min IP
    splittedlist.sort()
    maxip = splittedlist[-1]
    minip = splittedlist[0]

    # Calculate mask
    mask = 0xFFFFFFFF ^ ip_to_int(*minip) ^ ip_to_int(*maxip)

    # CIDR
    cidr = bin(mask)[2:].find('0')

    # Calculate new mask according to CIDR
    mask = int(bin(mask)[2:cidr + 2].ljust(32, '0'), 2)

    # Calculate netmask
    netmask = [(mask & (0xFF << (8 * n))) >> 8 * n for n in (3, 2, 1, 0)]

    # Calculate network start
    netstart = [minip[x] & netmask[x] for x in range(0, 4)]

    return ('.'.join([str(chk) for chk in netstart]), cidr)

## LOGIC
for f in sorted(glob.glob(filepath), reverse=True):
    if f.endswith('.gz'):
        fh = gzip.open(f, 'rb')
    else:
        fh = open(f, 'rb')

    for l in fh:
        if isinstance(l, bytes):
            l = l.decode()

        m = lineregex.match(l)

        if not m:
            continue

        dt = datetime.strptime(m.group('TIME'), timeformat)
        fdt = float(dt.strftime('%s.%f'))
        if fdt < mintime:
            continue

        ip = m.group('HOST')
        ipb = '.'.join(ip.split('.')[:3])

        if ipb in ipblocks:
            ipblocks[ipb]['ban'] += 1
            if ip not in ipblocks[ipb]['ip']:
                ipblocks[ipb]['ip'].append(ip)
        else:
            ipblocks[ipb] = {
                'ban':  1,
                'ip':   [ip, ]
            }

    fh.close()

# Filter then sort the offenders by order or higher offense
offenders = [
    {
        'ban': v['ban'],
        'subnet': get_subnet(v['ip']),
        'ipn': len(v['ip']),
        'iplist': v['ip']
    }
    for k, v in ipblocks.items() if (
        len(v['ip']) >= min_ips
        and v['ban'] >= maxretry
    )
]

if excludeban:
    iptablesL = subprocess.Popen(
        ['iptables', '-n', '-L', 'fail2ban-%s' % subnetsjail],
        stdout=subprocess.PIPE)

    out = iptablesL.communicate()[0]

    banList = dict(re.findall(
        '\nDROP[^\n]*?'
        '(?P<HOST>(?:[0-9]{1,3}\.){3}[0-9]{1,3})'
        '/'
        '(?P<CIDR>[0-9]{1,2})(?![0-9])', out))

for o in offenders:
    if excludeban:
        net, cidr = o['subnet']
        if net in banList:
            if int(banList[net]) > cidr:
                # We have to remove the previous ban in order for the
                # new one, larger, to be applied
                iptablesD = subprocess.Popen(
                    ['iptables', '-D', 'fail2ban-%s' % subnetsjail,
                     '-s', '%s/%s' % (net, banList[net]), '-j', 'DROP'],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                out = iptablesD.communicate()[0].rstrip()
                if iptablesD.returncode != 0:
                    logger.error(
                        "while unbanning %s/%s: %s" % (
                            net, banList[net], out))
            else:
                # We just don't log this subnet
                continue

    logban(o)
