import asyncio
from contextvars import ContextVar
from browser.actor import Actor


async def test_disconnected_request_does_not_cancel_accepted_operation():
    actor=Actor()
    await actor.start()
    started,release,completed=asyncio.Event(),asyncio.Event(),asyncio.Event()
    results=[]
    async def operation():
        started.set()
        await release.wait()
        results.append('completed once')
        completed.set()
        return 'receipt'
    request=asyncio.create_task(actor.invoke(operation))
    await started.wait()
    request.cancel()
    await asyncio.gather(request,return_exceptions=True)
    release.set()
    await asyncio.wait_for(completed.wait(),1)
    assert results==['completed once']
    await actor.stop()


async def test_request_context_does_not_own_browser_operation():
    request_context=ContextVar('temporary_mcp_context',default=None)
    actor=Actor()
    await actor.start()
    token=request_context.set('transient request')
    async def operation():return request_context.get()
    assert await actor.invoke(operation) is None
    request_context.reset(token)
    await actor.stop()
