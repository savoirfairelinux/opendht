#!/usr/bin/env python3
# Copyright (c) 2014-2026 Savoir-faire Linux Inc.
# SPDX-License-Identifier: MIT

import asyncio
import time

from opendht import aio as dht


async def main():
	config = dht.DhtConfig()
	config.setRateLimit(-1, -1)

	ping_node = dht.DhtRunner()
	pong_node = dht.DhtRunner()
	# ping_node.enableLogging()
	# pong_node.enableLogging()
	# ping_node.bootstrap("bootstrap.jami.net", "4222")
	ping_node.run(config=config)
	pong_node.run(config=config)
	await pong_node.ping(ping_node.getBound())

	net = [dht.DhtRunner() for _ in range(1, 10)]
	for n in net:
		n.run(config=config)
		n.ping(ping_node.getBound())

	MAX = 2048
	counter = 0
	loc_ping = dht.InfoHash.get(f"ping-{ping_node.getNodeId()}")
	loc_pong = dht.InfoHash.get(str(loc_ping))

	async def ponger(listener_node: dht.DhtRunner, listen_key, responder_node: dht.DhtRunner, respond_key):
		nonlocal counter
		with listener_node.listen(listen_key) as listener:
			async for value, expired in listener:
				if not expired:
					await responder_node.put(respond_key, dht.Value(b"hey"))
					counter += 1
					if counter >= MAX:
						break

	start = time.time()
	await asyncio.gather(
		ponger(ping_node, loc_ping, pong_node, loc_pong),
		ponger(pong_node, loc_pong, ping_node, loc_ping),
		pong_node.put(loc_ping, dht.Value(b"hey"))
	)
	duration = time.time() - start

	await asyncio.gather(
		ping_node.shutdown(),
		pong_node.shutdown(),
		*(n.shutdown() for n in net),
	)

	print(MAX, "ping-pong done, took", duration, "s")
	print(1000 * duration / MAX, "ms per rt", MAX / duration, "rt per s")


if __name__ == "__main__":
	asyncio.run(main())
