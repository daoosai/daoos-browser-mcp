"""Browser commands execute outside transient HTTP/MCP request cancellation scopes.
A disconnected client can retrieve the durable action receipt instead of causing
an ambiguous replay. This actor is not an AI executor or a separate service.
"""
import asyncio
from .store import Denied


class Actor:
    def __init__(self):
        self.queue = asyncio.Queue(maxsize=32)
        self.task = None
        self.stopping = False

    async def start(self):
        self.task = asyncio.create_task(self.worker(), name="browser-commands")

    async def invoke(self, method, *args, **kwargs):
        if self.stopping: raise Denied("service_stopping")
        future = asyncio.get_running_loop().create_future()
        # Retrieve a failure even when the HTTP client disconnects before completion.
        future.add_done_callback(lambda f: None if f.cancelled() else f.exception())
        try: self.queue.put_nowait((future, method, args, kwargs))
        except asyncio.QueueFull: raise Denied("command_queue_full") from None
        return await asyncio.shield(future)

    async def worker(self):
        while True:
            future, method, args, kwargs = await self.queue.get()
            try:
                result = await method(*args, **kwargs)
                if not future.done(): future.set_result(result)
            except asyncio.CancelledError:
                if not future.done(): future.set_exception(Denied("service_stopping"))
                raise
            except Exception as exc:
                if not future.done(): future.set_exception(exc)
            finally:
                self.queue.task_done()

    async def stop(self):
        self.stopping = True
        while not self.queue.empty():
            future, *_ = self.queue.get_nowait()
            if not future.done(): future.set_exception(Denied("service_stopping"))
            self.queue.task_done()
        try: await asyncio.wait_for(self.queue.join(), 35)
        except TimeoutError: pass
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
