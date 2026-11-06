import re
import ipaddress
from datetime import datetime, timezone
from .models import Event
PREFIX = re.compile(r'^(?P<stamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d\d-\d\dT\S+)\s+(?P<host>\S+)\s+sshd(?:-session)?(?:\[\d+\])?:\s+(?P<message>.*)$')
LOGIN = re.compile(r'^(?P<outcome>Failed|Accepted) (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+(?:\s|$)')


def parse_line(raw, file, line, year, offset):
    match = PREFIX.match(raw)
    if not match:
        return None
    login = LOGIN.match(match['message'])
    if not login:
        if match['message'].startswith(('Failed ', 'Accepted ')):
            raise ValueError('unsupported or malformed login message')
        return None
    stamp = match['stamp']
    if re.match(r'^\d{4}-', stamp):
        moment = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=offset)
    else:
        moment = datetime.strptime(f'{year} {stamp}', '%Y %b %d %H:%M:%S').replace(tzinfo=offset)
    address = str(ipaddress.ip_address(login['ip']))
    return Event(moment.astimezone(timezone.utc), match['host'], login['user'], address,
                 login['outcome'].lower(), login['method'], str(file), line, raw.rstrip('\n'))

