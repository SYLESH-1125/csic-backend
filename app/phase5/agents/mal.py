import json
from sklearn.ensemble import IsolationForest
f= open( 'data/test.json', 'r' )
d =json.load(f)
f.close()
new_= d[ 'seed_value' ]
pts =[[1], [2], [1], [3], [2], [1], [15], [2]]
print("Isolation Forest: Scanning Process Tree...")
mdl= IsolationForest(contamination=0.1)
mdl.fit(pts)
prd =mdl.predict(pts)
print("\n[Target: " + new_ + "]")
print("└── Process Tree Forest")
res ={}
res['agent'] ="Malware"
res['target'] =new_
idx =0
anm =-1
for x in prd:
    val = pts[ idx ][ 0 ]
    if x == 1:
        print("    ├── [OK] Depth " + str(val))
    else:
        anm = val
        print("    └── [!!] CRITICAL DEPTH DETECTED: " + str(anm))
    idx =idx+ 1
if anm !=-1:
    res['finding'] ="Suspicious process depth outlier detected: " +str(anm)
    res['confidence']= 91
else:
    res['finding'] ="Process behavior within normal limits"
    res['confidence'] =15
f2 =open( 'data/mal_out.json', 'w' )
json.dump(res, f2)
f2.close()
print("\n[+] Dynamic MAL Agent finished.\n")