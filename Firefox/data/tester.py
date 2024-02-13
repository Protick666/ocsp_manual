from csv import reader

def get_websites():
    websites = []
    with open('top-1m.csv') as read_obj:
        csv_reader = reader(read_obj)
        index = 0
        for row in csv_reader:
            index = index + 1
            if index == 1:
                continue
            websites.append(row[1])
    return websites

wbs = get_websites()
a = 1
p = [e for e in wbs if 'ra.it' in e and e.startswith("p") ]
cks = [e for e in wbs if 'vo.it' in e and e.startswith("co") ]

# 'piacenzasera.it'
# 'pitagora.it'
# 'referer' => 'https://###.co###vo.it/', -> 'codingcreativo.it'

a = 1