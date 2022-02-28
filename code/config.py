import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings['VERSION']
    APIPORT = '50105'
    MAX_SEARCH_LIMIT = 100000
    SEARCH_TIMEFRAME = 24   # hours

    SOURCE = 'RSA NetWitness'

    CTIM_DEFAULTS = {
        'schema_version': '1.1.4',
    }

    SIGHTING_DEFAULTS = {
        **CTIM_DEFAULTS,
        'confidence': 'High',
        'type': 'sighting',
        'source': SOURCE,
    }

    RELATIONS_DEFAULTS = {
        "origin": SOURCE,
        "relation": 'Connected_To'
    }
