import asyncio

class AsyncHandler:
    def __init__(self, concurrency=10):
        self.semaphore = asyncio.Semaphore(concurrency)

    async def run_task(self, task_func, *args, **kwargs):
        async with self.semaphore:
            return await task_func(*args, **kwargs)

    async def run_tasks(self, tasks):
        return await asyncio.gather(*tasks)