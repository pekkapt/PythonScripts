import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime


url="https://www.e-leclerc.pt/hipermercado-santa-maria-da-feira"

tab_combustivel = {}
combustiveisFileName = 'eleclerc_combustiveis.json'
datenow = datetime.today().strftime('%Y-%m-%d')#-%H:%M:%S

try:
    with open(combustiveisFileName) as json_file:
        tab_combustivelHistory = json.load(json_file)
except:
    print("file error")

page = requests.get(url)

soup = BeautifulSoup(page.content, 'html.parser')


zona_combustivel = soup.find("div", {"class":"div_100 menu_paginas overflow"})
tag_combustivel = zona_combustivel.findAll("div", {"class": "menu_paginas_combustivel"})
local="feira"
tab_combustivel[datenow] = {}
tab_combustivel[datenow][local] = {}

for combustivel in tag_combustivel:
    tipo_combustivel = combustivel.find("div", {"class": "menu_pags_txt"}).get_text()
    preco_combustivel = combustivel.find("div", {"class": "menu_pags_preco"}).get_text()
    tab_combustivel[datenow][local][tipo_combustivel]=preco_combustivel
    print(local + " " + datenow + " " + tipo_combustivel + ":" + preco_combustivel)


tab_combustivelHistory.update(tab_combustivel) 

print(json.dumps(tab_combustivelHistory, indent=4, sort_keys=True))  

with open(combustiveisFileName, 'w') as outfile:
    json.dump(tab_combustivelHistory, outfile, indent=4, sort_keys=True)
 
