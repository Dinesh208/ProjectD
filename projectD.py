from review import parse
# from bs4 import BeautifulSoup
from progress.bar import Bar
# import db as dbHandler
import urllib.parse
import subprocess
import requests
import pandas as pd
# import numpy as np
import webbrowser
from itertools import cycle
import json


def write_results(output, results):
    """Writing result as an HTML file
    
        Using pandas to create an HTML table and save it as an HTML file
    
    Args:
        output (str): path to the output file
        results (list): a list contains results
    """

    f = open(output, 'w')
    name = []
    status = []
    info = []
    for result in results:
        name.append(result[0].replace('>', '&gt;').replace('<', '&lt;'))
        status.append(result[1])
        info.append(result[2])

    df_marks = pd.DataFrame({'Payload': name,
                             'Status': status,
                             'Type': info})

    color = 'background-color: {}'.format('#0CC0DF')
    # add style to dataframe
    s = df_marks.style.applymap(color_fail_red, subset=['Status'])
    # render dataframe as HTML
    html_content = '<html><head><style>body{{{};}}</style></head><body>{}</body></html>'.format(color, s.to_html())
    f.write(html_content)
    f.close()
    # open file
    webbrowser.open('file://'+str(output))


def color_fail_red(row):
    """Takes a scalar and returns a string with
    the CSS property `'background-color: red'` for fail
    strings, pass = green
    """
    color = 'background-color: {}'.format('red' if row == 'fail' else 'green')
    return color


def fire(mode, target, payload, header, count):
    """Firing payload to the target website
    
        Send payload to send it to the target website.
        Check the response and return the result. 
    
    Args:
        mode (str): tool mode = fuzzing / xss / sqli
        target (str): target website
        payload (str): payload that needs to be sent to the website
        header (json): HTML header
        count (int): count how many payloads are sent

    Returns:
        result (list): result of executed payload which includes information such as
        payload, type, and status
    """
    payload = urllib.parse.quote(payload.replace('\n', ''))

    r = requests.get(target.replace('projectD', payload), headers=header)
    
    status = 'pass' if r.status_code == 200 else 'fail'

    # Fuzzing mode then keep pass and fail, payload execution keep only pass
    if mode == 'xss' or mode == 'sqli':
        
        result = (urllib.parse.unquote(payload), status, mode)
        
    else:
        result = (urllib.parse.unquote(payload), status, mode)
    return result

def create_header(cookies):
    """Create HTML header
    
        Ask the user if they want to use a bypass WAF headers which are 
        X-Originating-IP:, X-Forwarded-For:, X-Remote-IP, and X-Remote-Addr.
        Mentioned headers can be used to bypass some WAF products
    
    Args:
        cookies (str): website cookies for bypassing auth

    Returns:
        header (json): HTML header
    """

    usr_input = input("[?] Do you want to add an extension header ?\nThe headers include X-Originating-IP:, X-Forwarded-For:, X-Remote-IP, X-Remote-Addr: \nThe mentioned header can be used for bypassing some WAF products. [y/n]")
    if usr_input.lower() == 'y':
        header = {'content-type': 'application/json',
               'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0',
               'Accept-Encoding': 'gzip,deflate,sdch',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
               'Connection': 'keep-alive',
               'X-Originating-IP': '127.0.0.1',
               'X-Forwarded-For': '127.0.0.1',
               'X-Remote-IP': '127.0.0.1', 
               'X-Remote-Addr': '127.0.0.1',
               'Cookie': cookies}
    else:
        header = {'content-type': 'application/json',
               'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0',
               'Accept-Encoding': 'gzip,deflate,sdch',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
               'Connection': 'keep-alive',
               'Cookie': cookies}
    return header


def read_payload(mode, target, dbPath, header):
    """Read payloads from the database and firing it to the target website
    
        Read payload from the given path then firing the payloads to the target website
        the process bar is shown when the tool starts sending payloads.
    
    Args:
        mode (str): tool mode = fuzzing / xss / sqli
        target (str): target website
        dbPath (str): path to the database needed to be read
        header (json): HTML header

    Returns:
        results (list): results of executed payloads
    """
    count = 0
    results = []

    # read payloads
    with open(dbPath, 'r') as payloads:
        payloads = payloads.readlines()
        bar = Bar('Processing', max=len(payloads))        
        for payload in payloads:
            count = count + 1
            result = fire(mode, target, payload, header, count)
            if result != None:
                results.append(result)
            bar.next()
    bar.finish()  
    return results


logo = """ 
  _____    _____     ____         _   ______    _____   _______   _____  
 |  __ \  |  __ \   / __ \       | | |  ____|  / ____| |__   __| |  __ \ 
 | |__) | | |__) | | |  | |      | | | |__    | |         | |    | |  | |
 |  ___/  |  _  /  | |  | |  _   | | |  __|   | |         | |    | |  | |
 | |      | | \ \  | |__| | | |__| | | |____  | |____     | |    | |__| |
 |_|      |_|  \_\  \____/   \____/  |______|  \_____|    |_|    |_____/ 
                                                                    

"""
print(logo)
# parse the given input
args = parse()

if args[0] == 'wafw00f': # footprinting
    target = args[1]
    print('[+] The target website is %s' % target)
    print('[+] Executing wafw00f')
    output = subprocess.getoutput('python3 wafw00f-master/wafw00f/main.py {}'.format(target))
    print(output)
else:
    mode, target, dbPath, output, cookies = args # fixthis
    # fix cookies's format
    if cookies is not None:
        cookies = cookies.replace(',', '; ').replace(':', '=') + ";"
    # prepare HTML header
    header = create_header(cookies)
    print('[+] The target website is %s' % target)
    if dbPath == 'db/fuzz/': # default fuzzing
        results = read_payload('fuzz xss', target, dbPath+'xss.txt', header) # read fuzz/xss.txt
        result2 = read_payload('fuzz sqli', target, dbPath+'sqli.txt', header) # read fuzz/sqli.txt then append to the previous results
        results = results + result2
    elif dbPath == 'db/ssti.txt':  # ssti
            results = read_payload('ssti', target, dbPath, header)  # read ssti.txt
    else:  # xss or sqli
        results = read_payload(mode, target, dbPath, header)
    print('[+] The result is saved in %s' % output)
    # writing output as .html
    write_results(output, results)
