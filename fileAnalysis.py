import json
from requests import *
from simplegmail import Gmail

gmail =Gmail()

def runFile(apikey,hash):
  api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
  params = dict(apikey=apikey, resource=hash, scan=0)
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

def fileAnalysis(id):
  todoOk=False
  messages= gmail.get_unread_inbox()
  permitidos ={ 'txt', 'doc','docx','xls','ppt','rtf','odt','ods','pdf','zip','mp3','mov','mp4','qt','png','jpg','jpeg'}
  for message in messages:
    if message.id == id:
      if message.attachments:
        for attm in message.attachments:
          a=(attm.filename.split('.',0))
          b="".join(a)
          for i in permitidos:
            if i in b:
              todoOk=True
              return todoOk
  return todoOk