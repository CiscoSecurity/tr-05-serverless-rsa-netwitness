from http import HTTPStatus

from unittest.mock import patch
from pytest import fixture

from tests.unit.api.utils import get_headers
from tests.unit.conftest import mock_api_response
from tests.unit.payloads_for_tests import (EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
                                           EXPECTED_PAYLOAD_SEARCH,
                                           EXPECTED_RESPONSE_OBSERVE,)


def routes():
    yield '/observe/observables'


def expected_responses():
    yield mock_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    yield mock_api_response(payload=EXPECTED_PAYLOAD_SEARCH)


def ids():
    yield '63b847c9-4429-4328-804a-5a06c2d03f9f'
    yield 'c54d2bfa-a710-42af-92f2-f3a628b89c15'
    yield '806b4eb2-18da-4322-bf7d-3701823a87e5'
    yield 'da992d05-3f6e-4433-89cd-67208df067c8'
    yield '78a6ba52-4353-43b2-9308-b5886f387682'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json_value():
    return [{'type': 'ip', 'value': ''}]


@patch('requests.get')
def test_enrich_call_with_valid_jwt_but_invalid_json_value(
        mock_request,
        route, client, valid_jwt, invalid_json_value,
        invalid_json_expected_payload
):
    mock_request.return_value = \
        mock_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    response = client.post(route,
                           headers=get_headers(valid_jwt()),
                           json=invalid_json_value)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        "{0: {'value': ['Field may not be blank.']}}"
    )


@fixture(scope='module')
def valid_json():
    return [{'type': 'ip', 'value': '52.3.199.104'}]


@patch('api.mapping.uuid4')
@patch('requests.get')
def test_enrich_call_success(mock_request, mock_id,
                             route, client, valid_jwt, valid_json):
    mock_id.side_effect = ids()
    mock_request.side_effect = expected_responses()
    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == EXPECTED_RESPONSE_OBSERVE
