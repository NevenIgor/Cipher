import time


def tracer(func):
    def wrapper(*args, **kwargs):
        time1 = time.time()
        result = func(*args, **kwargs)
        time2 = time.time()
        print(f'\nTracer called by func {func.__name__}()')
        #print(f'args: {args}')
        #print(f'kwargs: {kwargs}')
        #print(f'Returns: {result}')
        print(f'Running time: {time2 - time1}')
        return result
    return wrapper
