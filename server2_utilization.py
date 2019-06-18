import psutil
import time
import json
import csv

res = open("result/server2_utilization.csv", "wb")
writer = csv.writer(res, delimiter=',')

while True:
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    msg = json.dumps(
        {"cpu": cpu, "mem": mem})
    line = [cpu, mem]
    print line
    writer.writerow(line)
    time.sleep(1)
