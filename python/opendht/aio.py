# Copyright (c) 2014-2026 Savoir-faire Linux Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
from __future__ import annotations

import asyncio
from typing import Any, Callable, Iterable, List, Optional, Tuple

from . import _core as _dht

# Re-export core types for convenience
from ._core import InfoHash, Value, ValueType, Where, SockAddr, PublicKey, PkId, DhtConfig, Identity


class _Listener:
    """Async iterator around DHT listen callback.

    Yields tuples (Value, expired: bool).
    """

    __slots__ = ("_runner", "_token", "_loop", "_queue", "_closed")

    def __init__(self, runner: DhtRunner, key: InfoHash) -> None:
        self._runner = runner
        self._loop = runner._loop
        self._queue: asyncio.Queue[Tuple[Value, bool]] = asyncio.Queue()
        self._closed = False

        def _on_value(v: Value, expired: bool) -> bool:
            if self._closed:
                return False
            self._loop.call_soon_threadsafe(self._queue.put_nowait, (v, expired))
            return True  # continue listening

        self._token = self._runner._dht.listen(key, _on_value)

    def __enter__(self) -> _Listener:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.cancel()

    def __aiter__(self) -> _Listener:
        return self

    async def __anext__(self) -> Tuple[Value, bool]:
        if self._closed:
            raise StopAsyncIteration
        item = await self._queue.get()
        if item is None:
            self._closed = True
            raise StopAsyncIteration
        return item

    def cancel(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._runner._dht.cancelListen(self._token)
        finally:
            # Unblock any pending __anext__
            self._queue.put_nowait(None)


class _GetStream:
    """Async iterator around DHT get callback.

    Yields Value instances as they are found, then ends.
    Raises on failure.
    """
    __slots__ = ("_runner", "_loop", "_queue", "_closed", "_error")

    def __init__(
        self,
        runner: DhtRunner,
        key: InfoHash,
        where: Optional[Where],
        filter: Optional[Callable[[Value], bool]],
    ) -> None:
        self._runner = runner
        self._loop = runner._loop
        self._queue: asyncio.Queue[Optional[Value]] = asyncio.Queue()
        self._closed = False
        self._error: Optional[BaseException] = None

        def _on_value(v: Value) -> bool:
            # Called on DHT thread
            if self._closed:
                return False
            self._loop.call_soon_threadsafe(self._queue.put_nowait, v)
            return True

        def _on_done(ok: bool, _nodes: Iterable[Any]) -> None:
            # Called on DHT thread
            if self._closed:
                return
            if not ok:
                self._error = RuntimeError("DHT get failed")
            self._loop.call_soon_threadsafe(self._queue.put_nowait, None)

        self._runner._dht.get(key, _on_value, _on_done, filter, where)

    def __enter__(self) -> _GetStream:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.cancel()

    def __aiter__(self) -> _GetStream:
        return self

    async def __anext__(self) -> Value:
        if self._closed:
            raise StopAsyncIteration
        item = await self._queue.get()
        if item is None:
            self._closed = True
            if self._error is not None:
                raise self._error
            raise StopAsyncIteration
        return item

    def cancel(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Unblock any pending __anext__
        self._queue.put_nowait(None)


class DhtRunner:
    """Async wrapper around opendht.DhtRunner.
    """

    __slots__ = ("_dht", "_loop", "_config", "_bootstrap")

    def __init__(
        self,
        *,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        core: Optional[_dht.DhtRunner] = None,
        config: Optional[DhtConfig] = None,
        bootstrap: Optional[Iterable[Tuple[str, Optional[str]]]] = None,
    ) -> None:
        try:
            self._loop = loop or asyncio.get_running_loop()
        except RuntimeError:
            self._loop = asyncio.get_event_loop()
        self._dht = core or _dht.DhtRunner()
        self._config = config
        self._bootstrap = list(bootstrap) if bootstrap is not None else None

    def run(
        self,
        id: Optional[Identity] = None,
        is_bootstrap: bool = False,
        port: int = 0,
        ipv4: str = "",
        ipv6: str = "",
        config: Optional[DhtConfig] = None,
    ) -> None:
        cfg = config or self._config or DhtConfig()
        self._dht.run(id, is_bootstrap, port, ipv4, ipv6, cfg)
        if self._bootstrap:
            for host, port_str in self._bootstrap:
                self._dht.bootstrap(host, port_str)

    def bootstrap(self, host: str, port: Optional[str] = None) -> None:
        self._dht.bootstrap(host, port)

    async def ping(self, addr: SockAddr) -> bool:
        fut: asyncio.Future[bool] = self._loop.create_future()
        self._dht.ping(addr, lambda ok: self._loop.call_soon_threadsafe(fut.set_result, bool(ok)))
        return await fut

    def get(
        self,
        key: InfoHash,
        *,
        where: Optional[Where] = None,
        filter: Optional[Callable[[Value], bool]] = None,
    ):
        # Return a streaming iterator of values; it ends on completion and raises on failure.
        return _GetStream(self, key, where, filter)

    async def getAll(
        self,
        key: InfoHash,
        *,
        where: Optional[Where] = None,
        filter: Optional[Callable[[Value], bool]] = None,
    ) -> List[Value]:
        """Collect all values for a key and return them as a list."""
        results: List[Value] = []
        async for v in self.get(key, where=where, filter=filter):
            results.append(v)
        return results

    async def getFirst(
        self,
        key: InfoHash,
        *,
        where: Optional[Where] = None,
        predicate: Optional[Callable[[Value], Any]] = None,
        filter: Optional[Callable[[Value], bool]] = None,
    ) -> Optional[Value]:
        """Return the first value matching an (optionally async) predicate, or None."""
        with self.get(key, where=where, filter=filter) as stream:
            async for value in stream:
                if predicate is None:
                    return value
                result = predicate(value)
                if asyncio.iscoroutine(result):
                    result = await result
                if result:
                    return value
        return None

    async def put(self, key: InfoHash, val: Value, *, permanent: bool = False) -> bool:
        fut: asyncio.Future[bool] = self._loop.create_future()

        def _done(ok: bool, _nodes: Iterable[Any]) -> None:
            self._loop.call_soon_threadsafe(fut.set_result, bool(ok))

        self._dht.put(key, val, _done, permanent)
        return await fut

    async def putSigned(self, key: InfoHash, val: Value, *, permanent: bool = False) -> bool:
        fut: asyncio.Future[bool] = self._loop.create_future()

        def _done(ok: bool, _nodes: Iterable[Any]) -> None:
            self._loop.call_soon_threadsafe(fut.set_result, bool(ok))

        self._dht.putSigned(key, val, _done, permanent)
        return await fut

    async def putEncrypted(
        self,
        key: InfoHash,
        to: InfoHash | PublicKey | PkId,
        val: Value,
        *,
        permanent: bool = False,
    ) -> bool:
        fut: asyncio.Future[bool] = self._loop.create_future()

        def _done(ok: bool, _nodes: Iterable[Any]) -> None:
            self._loop.call_soon_threadsafe(fut.set_result, bool(ok))

        self._dht.putEncrypted(key, val, to, _done, permanent)
        return await fut

    def listen(self, key: InfoHash) -> _Listener:
        return _Listener(self, key)

    async def cancelListen(self, listener: _Listener) -> None:
        await listener.cancel()

    async def shutdown(self) -> None:
        fut: asyncio.Future[None] = self._loop.create_future()
        self._dht.shutdown(lambda: self._loop.call_soon_threadsafe(fut.set_result, None))
        await fut
    
    async def join(self) -> None:
        await asyncio.to_thread(self._dht.join)

    async def __aenter__(self):
        if not self.isRunning():
            self.run()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.isRunning():
            try:
                await self.shutdown()
            finally:
                await self.join()
        return False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._dht, name)
