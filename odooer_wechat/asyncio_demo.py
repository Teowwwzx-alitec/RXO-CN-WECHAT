import asyncio
from functools import partial
import sys,os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

import time

async def download(url):
    print("start download url"+url)
    # time.sleep(2)
    await asyncio.sleep(2)
    print("end download url"+url)
    return "hello world"

if __name__ == "__main__":
    start = time.time()
    loop = asyncio.get_event_loop()
    # loop.run_until_complete(download("www.baidu.com"))
    # loop.run_until_complete(asyncio.wait([download("www.baidu.com") for i in range(2)]))

    # loop.run_until_complete(loop.create_task(download("www.baidu.com")))
    # loop.run_until_complete(asyncio.gather(download("www.baidu.com")))

    # tasks = [download("www.baidu.com") for i in range(2)]
    # ret = loop.run_until_complete(asyncio.gather(*tasks))

    future = asyncio.gather(download("www.baidu.com"))

    def callback(url, future): # 协称在return之前的回调
        print("回调了:", url)
        
    future.add_done_callback(partial(callback, "www.baidu.com")) #利用partial函数包装callback，因为add_done_callback添加回调只接受一个参数,所以这里必须得用partial包装成一个函数，那相应的callback需要在增加一个参数url，而且这个url必须放在参数前面，这样的话我们就可以在回调的时候传递多个参数了。
    loop.run_until_complete(future)
    print("协称运行的结果：", future.result())

    print(time.time()-start)
