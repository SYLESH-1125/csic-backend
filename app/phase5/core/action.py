import json
import urllib.request
import os
from dotenv import load_dotenv
load_dotenv()
new_ =os.getenv( 'GEMINI_KEY' )
f =open( 'data/merged_triage.json', 'r' )
d =json.load(f)
f.close()
c1 =d[ 'id_data' ][ 'confidence' ]
c2 =d[ 'mal_data' ][ 'confidence' ]
c3 =d[ 'net_data' ][ 'confidence' ]
c4 =d[ 'dat_data' ][ 'confidence' ]
arr =[ 0, 0, 0, 0 ]
arr[ 0 ] =c1
arr[ 1 ] =c2
arr[ 2 ] =c3
arr[ 3 ] =c4
mx =max(arr)
prm ="Analyze this cyber threat data and write a short summary: "
prm =prm+ str(d)
url ="https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" +new_
dat ={}
dat[ 'contents' ] =[ { 'parts': [ { 'text': prm } ] } ]
req =urllib.request.Request(url, method='POST')
req.add_header('Content-Type', 'application/json')
jsn =json.dumps(dat).encode('utf-8')
res =urllib.request.urlopen(req, data=jsn)
out =res.read().decode('utf-8')
fin =json.loads(out)
txt =fin[ 'candidates' ][ 0 ][ 'content' ][ 'parts' ][ 0 ][ 'text' ]
print(txt)
f2 =open( 'data/final_report.json', 'w' )
res2 ={}
res2[ 'target' ] =d[ 'id_data' ][ 'target' ]
res2[ 'max_confidence' ] =mx
res2[ 'ai_summary' ] =txt
json.dump(res2, f2)
f2.close()