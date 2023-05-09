import logging.config
import logging
import shodan
import json
import time
#Logger
logger = logging.getLogger('LOGGER')
logger.setLevel(logging.INFO)
handler = logging.FileHandler('mylog.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logging.info('')

import configparser
config = configparser.RawConfigParser()
config.read('CONFIG_FILE')
SHODAN_API = config.get('SHODAN', 'API_KEY')

#rate limiter
RATE_LIMIT = 2
def RateLimited(maxPerSecond):
    minInterval = 1.0 / float(maxPerSecond)
    def decorate(func):
        lastTimeCalled = [0.0]
        def rateLimitedFunction(*args, **kargs):
            elapsed = time.perf_counter() - lastTimeCalled[0]
            leftToWait = minInterval - elapsed
            if leftToWait > 0:
                time.sleep(leftToWait)
            ret = func(*args, **kargs)
            lastTimeCalled[0] = time.perf_counter()
            return ret
        return rateLimitedFunction
    return decorate

#host searches
@RateLimited(RATE_LIMIT)
def shodan_host(shodan_api, search_ip):
    try:
        my_query = f'net:"{search_ip}"'
        host_results = shodan_api.host(my_query, history=False, minify=False)
        return host_results
    except:
        return("issue returning host results")
        
#search cursor searches
@RateLimited(RATE_LIMIT)
def shodan_search_cursor(shodan_api, search_ip):
    try:
        my_query = f'net:"{search_ip}"'
        results = shodan_api.search_cursor(my_query, minify=True ,retries=5)
        return results
    except:
        return("issue returning search cursor")

#shodan data to search for
list_of_keys = [
    'timestamp',
    'ip_str',
    'port',
    'data',
    'product',
    'version',
]

#query must be a list of ip(s)
def shodan_searcher(query):
      shodan_api = shodan.Shodan(SHODAN_API)  
      shodan_results = [] 
      for i in query:
            logger.info(f'Scanning.... {i}')
            try: 
                  shodan_generator = shodan_search_cursor(shodan_api, i)  
                  clean_banners = filtered_list(shodan_generator)        
                  for i in clean_banners:
                        shodan_results.append(i)
            except:
                  logger.info(f'Issue on shodan_searcher() looping through search_ip list')
      json_results = json.dumps(shodan_results, indent=2)
      return(json_results)

#create and return a list with only data we're interested in using
def filtered_list(generator_test):
    shodan_list = []
    shodan_banners = [banner for banner in generator_test]
    for banner in shodan_banners:
        temp_dict = {}            
        for key, value in recursive_dict(banner):    
            temp_dict[key] = value            
        shodan_list.append(temp_dict)                
    return shodan_list

#recursively checks all keys and values in a dictionary, compares it to a list of data we want, yield the data
def recursive_dict(dictionary):
    for key, value in dictionary.items():
        if type(value) is dict:
            #if a value is a dictionary iterate through it
            yield from recursive_dict(value)
        else:
            #if its not a dictionary print out the pair
            for i in list_of_keys:
                if key == i:
                    yield (key, value)

if __name__ == "__main__":

      #ill make interacting with the program nicer, later..
      shodan_result = shodan_searcher(['<ip>'])
      print(shodan_result)
