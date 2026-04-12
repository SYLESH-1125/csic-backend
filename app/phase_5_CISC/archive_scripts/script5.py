import sys

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    text = f.read()

old_bg = '''backgroundImage: 'url("/templates/' + coverId + '/cover_' + coverId.replace('template_','') + '.png")','''
new_bg = '''backgroundImage: 'url("/templates/template_1/cover_' + coverId + '.png")','''

if old_bg in text:
    text = text.replace(old_bg, new_bg)
    with open(sys.argv[1], 'w', encoding='utf-8') as f:
        f.write(text)
    print("Updated print page URL")
else:
    print("Not found")
