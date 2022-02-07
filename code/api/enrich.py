from functools import partial

from flask import Blueprint, g

from api.schemas import ObservableSchema
from api.mapping import Mapping
from api.utils import (get_json, jsonify_data, query_sightings,
                       jsonify_result, get_credentials)

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    credentials = get_credentials()
    observables = get_observables()

    g.sightings = []
    for observable in observables:
        response = query_sightings(observable['value'], credentials)
        for event in response:
            mapping = Mapping()
            g.sightings.append(mapping.sighting(observable, event))

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_observables()
    return jsonify_data([])
