import json
from requests import *

def runWeb(apikey,url):
  api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
  params = dict(apikey=apikey, resource=url, scan=0)
  response = get(api_url, params=params)
  resPositivos=True
  detectores=''
  if response.status_code == 200:
    jsonweb=response.json()
    for i in jsonweb:
      if i == 'positives' and jsonweb[i] > 0:
        resPositivos = False
      if i == 'scans' and resPositivos == False:
        for j in jsonweb[i]:
          if jsonweb[i][j]['result'] != 'clean site' and jsonweb[i][j]['result'] != 'unrated site':
            if detectores == '':
              detectores = j
            else:
              detectores = detectores + ' && ' + j

    if resPositivos == True:
      return resPositivos
    else:
      return detectores
