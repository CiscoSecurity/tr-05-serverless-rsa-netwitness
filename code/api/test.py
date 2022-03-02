import requests
import time
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED

def testit(indicator):
    response = requests.get(indicator)
    print(response.text)


def enrich():
    values = ['https://ifconfig.me', 'https://ifconfig.me']
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(testit, values)

    print("finish")

enrich()