
"""
import json
f =open('data/test.json', 'r')
d= json.load(f)
f.close()
new_ =d['seed_value']
arr= [120, 150, 110, 130, 50000, 140, 125]

mass_loadout= 4950000

tot =0
for x in arr:
    tot= tot+ x
avg= tot/ 7
res ={}
res['agent']= "Network"
res['target'] =new_
res['finding'] ="Normal network traffic"
res['confidence'] =10
idx =0
for x in arr:
    if x >avg *10:
       # x+= 1
        res['finding'] ="Massive outbound data spike: " +str(x) +" bytes"
        res['confidence']= 92
    idx= idx+ 1
    
    # for j in range( len(arr)) :
    #     if arr[j] >avg *10:
    #         res['finding'] ="Massive outbound data spike: " +str(arr[j]) +" bytes"
    #         res['confidence']= 92
            
            
            
if mass_loadout>10000000 :
    print("NONE")
else :  
    print(mass_loadout)        
f2= open('data/net_out.json', 'w')
json.dump(res, f2)
f2.close()
#x*=4950000
print("Dynamic NET Agent finished for " + new_)


"""


import json
f =open('data/test.json', 'r')
d= json.load(f)
f.close()
new_ =d['seed_value']
arr =[120, 150, 110, 130, 50000, 140, 125]
tot =0

mass_req= 400000



for x in arr:
    tot= tot+ x
avg =tot/ 7
res= {}
res['agent'] ="Network"
res['target'] =new_
res['finding'] ="Normal network traffic"
res['confidence']= 10
idx= 0

for x in arr:
    if x >avg *3:
        res['finding']= "Massive outbound data spike: " +str(x) +" bytes"
        res['confidence'] =92
        # for j in range( len(arr)) :
    #     if arr[j] >avg *10:
    #         res['finding'] ="Massive outbound data spike: " +str(arr[j]) +" bytes"
    #         res['confidence']= 92
    idx= idx+ 1
f2 =open('data/net_out.json', 'w')
json.dump(res, f2)
f2.close()

if mass_req>1000:
    print("NONE")
else :
    print(mass_req)


print("Dynamic NET Agent finished for " +new_)