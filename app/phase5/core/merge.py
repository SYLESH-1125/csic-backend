import json
new_ ={}
f1= open('data/id_out.json', 'r')
new_['id_data'] =json.load(f1)
f1.close()
f2 =open('data/mal_out.json', 'r')
new_['mal_data']= json.load(f2)
f2.close()
f3= open('data/net_out.json', 'r')
new_['net_data'] =json.load(f3)
f3.close()


f4 = open('data/dat_out.json', 'r')
new_['dat_data']= json.load(f4)
f4.close()
out =open('data/merged_triage.json', 'w')
json.dump(new_, out)
out.close()
print("All specialist reports merged into merged_triage.json")