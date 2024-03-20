import json


countries_list = list()
states_list = dict()
cities_list = dict()
with open('./../fixtures/country_data.json', '+r') as file:
    data = json.load(file)
    # pprint.pprint(data)
    # country = data.
 

    for country in data:
        code = country['phone_code']
        code = code.replace('-', '')
        if not code[0] == '+':
            code = '+' + code
        temp = {
            'name':country['name'],
            'phone_code':code,
            'flag': country['emojiU'],
            'country_code':country['iso2'],
            'flag_emoji' : country['emoji']
        }
        countries_list.append(temp)


        states = country['states']
        temp_state = {
            country['name']:list()
        }
        states_list[country['name']] = list()
        for state in states:
            states_list[country['name']].append(state['name'])


            cities_list[state['name']] = list()

            cities = state['cities']
            for city in cities:
                cities_list[state['name']].append(city['name'])


        # states_list.append(temp_state)


with open('./../utils/countries.json', 'w') as file:
    json.dump(countries_list, file)

with open('./../utils/cities.json', 'w') as file:
    json.dump(cities_list, file)

with open('./../utils/states.json', 'w') as file:
    json.dump(states_list, file)

            # print(state['name'])
            # cities = state['cities']
            # for city in cities:
            #     print(city['name'])


