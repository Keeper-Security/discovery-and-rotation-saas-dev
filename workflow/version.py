#!python3

from datetime import datetime

now = datetime.utcnow()
year_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

second_since_month = int((now-year_month).total_seconds())
version_num = "{}.{}.{}".format(now.year, now.month, second_since_month)

print(version_num)
