from flask import Blueprint

from api.utils import jsonify_data, get_node_info, get_credentials

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    credentials = get_credentials()
    node_info = get_node_info(credentials)

    return jsonify_data({'status': 'ok'})
