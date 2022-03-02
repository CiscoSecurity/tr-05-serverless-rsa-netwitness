from functools import partial
from flask import Blueprint, g, current_app
from api.schemas import ObservableSchema
from api.mapping import Mapping
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from api.utils import (get_json, query_sightings,
                       jsonify_result, get_credentials)

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    credentials = get_credentials()
    observables = get_observables()
    max_search_limit = current_app.config['MAX_SEARCH_LIMIT']
    search_timeframe = current_app.config['SEARCH_TIMEFRAME']

    values = []
    for observable in observables:
        values.append(observable['value'])

    pool = ThreadPoolExecutor(5)
    futures = [pool.submit(query_sightings, value, credentials, search_timeframe, max_search_limit) for value in values]
    wait(futures, return_when=ALL_COMPLETED)

    for future in futures:
        responses = future.result()
        mapping = Mapping()
        g.sightings.append(mapping.sighting('127.0.0.1', responses))

    return jsonify_result()
