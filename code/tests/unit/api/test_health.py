from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture

from tests.unit.api.utils import get_headers
from tests.unit.payloads_for_tests import EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
from tests.unit.conftest import mock_api_response


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@patch('requests.get')
def test_health_call_success(mock_get,
                             route, client, valid_jwt):
    mock_get.return_value = \
        mock_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    # mock_request.return_value = mock_api_response()
    response = client.post(route, headers=get_headers(valid_jwt()))
    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}
