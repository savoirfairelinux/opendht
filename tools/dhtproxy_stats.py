import requests
import time

ts = time.time()

stats_total = {"users":0, "pushListenersCount":0, "listenCount":0, "totalListeners":0, "totalPermanentPuts":0, "timestamp": str(ts), "local_storage_size":0, "local_storage_values":0, "storage_size":0, "storage_values":0}

for i in range(80,101):
    print("Collecting stats for proxy " + str(i))
    response = requests.request('GET', f'http://127.0.0.1:{i}/node/stats')

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
            stats['totalPermanentPuts'] = int(result["totalPermanentPuts"])
            stats_total['totalPermanentPuts'] += int(result["totalPermanentPuts"])
        except:
            pass

        try:
            stats['local_storage_size'] = int(result["local_storage_size"])
            stats_total['local_storage_size'] += int(result["local_storage_size"])
        except:
            pass
        try:
            stats['local_storage_values'] = int(result["local_storage_values"])
            stats_total['local_storage_values'] += int(result["local_storage_values"])
        except:
            pass
        try:
            stats['storage_size'] = int(result["storage_size"])
            stats_total['storage_size'] += int(result["storage_size"])
        except:
            pass
        try:
            stats['storage_values'] = int(result["storage_values"])
            stats_total['storage_values'] += int(result["storage_values"])
        except:
            pass

        stats['timestamp'] = str(ts)

        #with open("stats_proxy_" + str(i), "a") as stat_file:
        #    stat_file.write(str(stats))
        #    stat_file.write('\n')

with open("stats_proxy_total", "w") as stat_file:
    stat_file.write(str(stats_total))
    stat_file.write('\n')