import yaml


def get_company_name(value: int):
    with open('../sniffing/bt_company_identifiers.yaml', 'r') as file:
        identifiers = yaml.safe_load(file)
        for identifier in identifiers['company_identifiers']:
            print(identifier["value"])
            if identifier['value'] == value:
                return identifier['name']
        return 'Unknown'


print(get_company_name(117))
