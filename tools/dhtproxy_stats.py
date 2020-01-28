import requests
import time

ts = time.time()

stats_total = {"users":0, "pushListenersCount":0, "listenCount":0, "totalListeners":0, "totalPermanentPuts":0, "timestamp": str(ts)}

for i in range(80,101):
    print("Collecting stats for proxy " + str(i))
    response = requests.request('STATS', 'http://dhtproxy.jami.net:' + str(i))

    if response.status_code == 200:
        result = response.json()

        stats = {}
        # Get Total users
        try:
            stats['users'] = int(int(result["putCount"])/2)
            stats_total['users'] += int(int(result["putCount"])/2)
        except:
            pass
        # Get android push
        try:
            stats['pushListenersCount'] = int(result["pushListenersCount"])
            stats_total['pushListenersCount'] += int(result["pushListenersCount"])
        except:
            pass
        # Get Listeners
        try:
            stats['listenCount'] = int(result["listenCount"])
            stats_total['listenCount'] += int(result["listenCount"])
        except:
            pass
        # Get permanents put nb
        try:
            stats['totalListeners'] = int(result["pushListenersCount"]) + int(result["listenCount"])
            stats_total['totalListeners'] += int(result["pushListenersCount"]) + int(result["listenCount"])
        except:
            pass
        try:
            total = 0
            for h,v in result["puts"].items():
                total += int(v)
            stats['totalPermanentPuts'] = total
            stats_total['totalPermanentPuts'] += total
        except:
            pass
        
        stats['timestamp'] = str(ts)

        with open("stats_proxy_" + str(i), "a") as stat_file:
            stat_file.write(str(stats))
            stat_file.write('\n')

with open("stats_proxy_total", "a") as stat_file:
    stat_file.write(str(stats_total))
    stat_file.write('\n')