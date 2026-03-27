import json
from sklearn.ensemble import IsolationForest
f= open('data/test.json', 'r')
d =json.load(f)
f.close()
new_= d['seed_value']
hrs =[[9], [10], [11], [14], [15], [9], [10], [13], [16], [3]]
print("Isolation Forest: Initializing Tree Structure...")
mdl= IsolationForest(contamination=0.1)
mdl.fit(hrs)
prd =mdl.predict(hrs)
print("\n[Target: " + new_ + "]")
print("└── Identity Forest")
res= {}
res['agent']= "Identity"
res['target'] =new_
idx =0
anm= -1
for x in prd:
    val = hrs[ idx ][ 0 ]
    if x == 1:
        print("    ├── [OK] Hour " + str(val))
    else:
        anm = val
        print("    └── [!!] ANOMALY DETECTED AT HOUR " + str(anm))
    idx =idx+ 1
if anm !=-1:
    res['finding'] ="Anomalous login time detected at hour " +str(anm)
    res['confidence']= 98
else:
    res['finding'] ="Normal login behavior"
    res['confidence'] =10
f2 =open('data/id_out.json', 'w')
json.dump(res, f2)
f2.close()
print("\n[+] Dynamic ID Agent finished.\n")