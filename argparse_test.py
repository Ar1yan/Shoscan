import configparser
import shodan
import logging
import time
import json
import argparse

# store your creds in a config file
# make sure to git ignore it
# -- or env variable 
config = configparser.RawConfigParser()
config.read('CONFIGS')
SHODAN_API = config.get('SHODAN', 'API_KEY')

#Logger
logger = logging.getLogger('LOGGER')
logger.setLevel(logging.INFO)
handler = logging.FileHandler('log_files.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logging.info('')

#shodan key's to search for
#you dont have to use this and can simply append the entire shodan_banners into shodan_list inside of filtered_list()
#but if you wanna filter out keys here's the spot :)
list_of_keys = [
    'timestamp',
    'ip_str',
    'port',
    'data',
    'product',
    'version',
    'domains',
    'hostnames',
    'data'
]

#rate limiter
RATE_LIMIT = 5
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

@RateLimited(RATE_LIMIT)
def shodan_host(shodan_api, search_ip):
    try:
        my_query = f'net:"{search_ip}"'
        host_results = shodan_api.host(my_query, history=False, minify=False)
        return host_results
    except:
        return("issue returning host results")

@RateLimited(RATE_LIMIT)
def shodan_search_cursor(shodan_api, search_ip):
    try:
        my_query = f'net:"{search_ip}"'
        results = shodan_api.search_cursor(my_query, minify=True ,retries=5)
        return results
    except:
        return("issue returning search cursor")

def recursive_dict(dictionary):
    for key, value in dictionary.items():
        if type(value) is dict:
            yield from recursive_dict(value)
        else:
            for i in list_of_keys:
                if key == i:
                    yield (key, value)

def filtered_list(generator_test):
    shodan_list = []
    shodan_banners = [banner for banner in generator_test]
    for banner in shodan_banners:
        temp_dict = {}            
        for key, value in recursive_dict(banner):    
            temp_dict[key] = value                   
        shodan_list.append(temp_dict)                
    return shodan_list

def shodan_searcher():
      shodan_api = shodan.Shodan(SHODAN_API)
      shodan_results = [] 
      ip_file = arguments.ip_file
      query_list = []
      with open(ip_file) as file:
            for line in file:
                  query_list.append(line)
            try: 
                  new_list = [x[:-1] for x in query_list]
                  single_string = ','.join(new_list)
                  shodan_generator = shodan_search_cursor(shodan_api, single_string) 
                  clean_banners = filtered_list(shodan_generator)                                                     
                  for i in clean_banners:
                        i["data"] = i["data"].replace("\n"," ")
                        i["data"] = i["data"].replace("\r"," ")
                        i["data"] = i["data"].replace("\\r"," ")
                        i["data"] = i["data"].replace("\\n"," ")
                        shodan_results.append(i)
            except Exception as e:
                  print(e)
      return(json.dumps(shodan_results, indent=2))

if __name__ == "__main__":
    parser_query = argparse.ArgumentParser()
    parser_query.add_argument('--ip_file',       '-if',  dest = 'ip_file', metavar='ip_file', type=str, help='ip_file')
    arguments = parser_query.parse_args()
    results = shodan_searcher()
    print(results)