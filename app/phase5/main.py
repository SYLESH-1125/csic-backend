import json

f = open('data/test.json', 'r')
d = json.load(f)
f.close()

s = d['seed_value']
i = d['investigator_id']

a1 = "ID check: " + s
a2 = "MAL check: " + s
a3 = "NET check: " + s
a4 = "DAT check: " + s

r = [a1, a2, a3, a4]
print(i)
print(r)