import json
f= open( 'data/test.json', 'r' )
d =json.load(f)
f.close()
new_= d[ 'seed_value' ]
rows =[ 5, 8, 4, 6, 7, 9000 ]
tot= 0
for x in rows:
    tot= tot+ x
avg= tot/ len(rows)
res ={}
res['agent'] ="Data"
res['target'] =new_
res['finding'] ="Normal database access"
res['confidence']= 12
for x in rows:
    if x > avg * 2:
        res['finding'] ="Database bulk-read anomaly: " +str(x) +" rows accessed"
        res['confidence']= 94
f2 =open( 'data/dat_out.json', 'w' )
json.dump(res, f2)
f2.close()
print("Dynamic DAT Agent finished for " +new_)