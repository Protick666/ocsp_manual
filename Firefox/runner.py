import subprocess
import time
import argparse
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from csv import reader
import logging
import time
from logging.handlers import RotatingFileHandler

split = 101
#logging.basicConfig(filename='timing.log', encoding='utf-8', level=logging.DEBUG)
logger = logging.getLogger('my_logger')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('log/my_log.log', maxBytes=5000000000000000000, backupCount=1000)
logger.addHandler(handler)

source_dir = "pcap/"
dest_dir = "dest/"

def start_tcp_dump(filename):
    #return
    p = subprocess.Popen(["tcpdump", "-w", "{}{}".format(source_dir, filename)], stdout=subprocess.PIPE)
    time.sleep(.5)
    return p

def end_tcp_dump(p):
    #return
    p.terminate()

def execute_cmd(command):
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output, error

def mv_files(filename):
    #return
    cmd = "mv {}{} {}".format(source_dir, filename, dest_dir)
    ans = execute_cmd(cmd)
    # if ans[1] is None:
    #     cmd = "rm {}{}".format(source_dir, filename)
    #     execute_cmd(cmd)


def get_options(browser_mode, ocsp_mode):
    from selenium.webdriver.firefox.options import Options
    options = Options()
    options.headless = True
    options.set_preference('security.pki.crlite_mode', 0)
    options.set_preference('security.tls.version.max', 3)
    return options

def get_websites():
    websites = []
    with open('data/top-1m.csv') as read_obj:
        csv_reader = reader(read_obj)
        index = 0
        for row in csv_reader:
            index = index + 1
            if index == 1:
                continue
            websites.append(row[1])
    return websites


def divide_chunks(l, n):
    # looping till length l
    for i in range(0, len(l), n):
        yield l[i:i + n]

# mode = 1 (cold cache)
# mode = 2 (warm cache)
# mode = 3 (normal)

def get_browser(browser_mode, options, ocsp_mode):
    try:
        #print("lul")
        if browser_mode == 'firefox':
            #print("gul")
            browser = webdriver.Firefox(executable_path="drivers/geckodriver", options=options)
            #print("uu")
        elif browser_mode == 'chrome':
            browser = webdriver.Chrome(executable_path="drivers/chromedriver", options=options)
        elif browser_mode == 'edge':
            # 100.0.1156.1/edgedriver_linux64.zip
            browser = webdriver.Edge(executable_path="drivers/msedgedriver", options=options)
        #print("lul")
        return browser
    except Exception as e:
        print( e)

def load_website(browser, website):
    browser.set_page_load_timeout(4)
    browser.get("https://{}".format(website))
    print(browser.title)
    time.sleep(.5)
    browser.quit()

def complete_chunk(chunk, browser_mode, filename, chunk_start_index, ocsp_mode, mode):
    temp_index = chunk_start_index - 1
    for website in chunk:
        try:
            temp_index = temp_index + 1
            options = get_options(browser_mode, ocsp_mode)
            browser = get_browser(browser_mode, options, ocsp_mode)
            logger.info('{}-{}, Rank: {}, Domain: {}, start: {}'.format(mode, ocsp_mode, temp_index, website, time.time()))
            load_website(browser, website)
            logger.info('{}-{}, Rank: {}, Domain: {}, end: {}'.format(mode, ocsp_mode, temp_index, website, time.time()))
        except Exception as e:
            try:
                browser.quit()
            except Exception as e:
                pass


def proc_chunk_entry(chunk, chunk_start_index, chunk_end_index, mode, browser_mode):
    # TODO add one -> all on : crlite also on
    for ocsp_mode in ['stapledon']:
        try:
            filename = "{}-{}-{}-{}.pcap".format('nsec', ocsp_mode, chunk_start_index, chunk_end_index)
            p = start_tcp_dump(filename=filename)
            complete_chunk(chunk, browser_mode, filename, chunk_start_index, ocsp_mode=ocsp_mode, mode=mode)
            end_tcp_dump(p)
            mv_files(filename)
        except Exception as e:
            pass

def runner(browser_mode, mode, intance):

    websites = get_websites()
    website_chunks = list(divide_chunks(websites, split))

    '''
        Name tcpdump
        mv files
        modes
    '''
    starting_chunk_index, ending_chunk_index = 0, len(website_chunks) - 1

    #
    while starting_chunk_index != ending_chunk_index:
        #print("in")
        next_index = starting_chunk_index + 1
        try:

            if starting_chunk_index % 5 == intance:

                proc_chunk_entry(website_chunks[starting_chunk_index], starting_chunk_index * split + 1,
                                 starting_chunk_index * split + split, mode, browser_mode)
        except Exception as e:
            print(e)
            pass
        # proc_chunk_entry(website_chunks[ending_chunk_index], ending_chunk_index * split + 1, min(ending_chunk_index * split + split, len(websites)), mode, browser_mode)

        starting_chunk_index = next_index
        # ending_chunk_index = ending_chunk_index - 1


parser = argparse.ArgumentParser()
parser.add_argument('--mode', type=str, required=True)
parser.add_argument('--dest', type=str, required=True)
parser.add_argument('--id', type=int, required=True)

args = parser.parse_args()
print(args)

dest_dir = args.dest
runner('firefox', args.mode, intance= args.id)

# dest_dir = 'dest/'
# runner('firefox', 'cold')

'''
    check if the commands work !!
    check if the pcap folder is there
'''

'''
run 
python3 browser_tester_firefox_for_range.py --mode normal --dest /source/ --id 4

'''



