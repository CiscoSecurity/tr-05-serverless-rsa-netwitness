from flask import Blueprint
from api.utils import jsonify_data

dashboard_api = Blueprint('dashboard', __name__)


@dashboard_api.route('/tiles', methods=['POST'])
def tiles():
    return jsonify_data([])


@dashboard_api.route('/tiles/tile', methods=['POST'])
def tile():
    return jsonify_data({})


@dashboard_api.route('/tiles/tile-data', methods=['POST'])
def tile_data():
    return jsonify_data({})
