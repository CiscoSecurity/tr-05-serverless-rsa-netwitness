import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings['VERSION']
    MAX_SEARCH_LIMIT = 500
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
