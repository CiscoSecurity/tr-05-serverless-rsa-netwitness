import json
from flask import current_app
from json.decoder import JSONDecodeError

import jwt
import requests
import datetime
from flask import request, current_app, jsonify, g
from jwt import InvalidSignatureError, DecodeError, InvalidAudienceError
from requests.exceptions import (InvalidURL, HTTPError,
                                 SSLError, ConnectionError)
from marshmallow import ValidationError

from api.errors import (AuthorizationError, InvalidArgumentError,
                        RSANetwitnessSSLError, RSANetwitnessConnectionError)
from api.schemas import NetwitnessSchema

NO_AUTH_HEADER = 'Authorization header is missing'
WRONG_AUTH_TYPE = 'Wrong authorization type'
WRONG_PAYLOAD_STRUCTURE = 'Wrong JWT payload structure'
WRONG_JWT_STRUCTURE = 'Wrong JWT structure'
WRONG_AUDIENCE = 'Wrong configuration-token-audience'
KID_NOT_FOUND = 'kid from JWT header not found in API response'
WRONG_KEY = ('Failed to decode JWT with provided key. '
             'Make sure domain in custom_jwks_host '
             'corresponds to your SecureX instance region.')
JWKS_HOST_MISSING = ('jwks_host is missing in JWT payload. Make sure '
                     'custom_jwks_host field is present in module_type')
WRONG_JWKS_HOST = ('Wrong jwks_host in JWT payload. Make sure domain follows '
                   'the visibility.<region>.cisco.com structure')


def get_public_key(jwks_host, token):
    """
    Get public key by requesting it from specified jwks host.
    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    expected_errors = (
        ConnectionError,
        InvalidURL,
        KeyError,
        JSONDecodeError,
        HTTPError
    )
    try:
        response = requests.get(f"https://{jwks_host}/.well-known/jwks")
        response.raise_for_status()
        jwks = response.json()

        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        kid = jwt.get_unverified_header(token)['kid']
        return public_keys.get(kid)

    except expected_errors:
        raise AuthorizationError(WRONG_JWKS_HOST)


def get_auth_token():
    """
    Parse and validate incoming request Authorization header.
    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """
    expected_errors = {
        KeyError: NO_AUTH_HEADER,
        AssertionError: WRONG_AUTH_TYPE
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_credentials():
    """
    Get Authorization token and validate its signature
    against the public key from /.well-known/jwks endpoint.
    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    expected_errors = {
        KeyError: JWKS_HOST_MISSING,
        AssertionError: WRONG_PAYLOAD_STRUCTURE,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        TypeError: KID_NOT_FOUND
    }
    token = get_auth_token()
    try:
        jwks_host = jwt.decode(
            token, options={'verify_signature': False}
        )['jwks_host']
        key = get_public_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=['RS256'], audience=[aud.rstrip('/')]
        )
        assert 'username' in payload
        assert 'password' in payload
        assert 'url' in payload

        return payload
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_json(schema):
    g.observables = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(g.observables)

    if message:
        raise InvalidArgumentError(message)

    return g.observables


def catch_errors(func):
    def wraps(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SSLError as error:
            raise RSANetwitnessSSLError(error)
        except (ConnectionError, InvalidURL):
            raise RSANetwitnessConnectionError
    return wraps


@catch_errors
def query_sightings(indicator, credentials):
    url = credentials.get('url')
    username = credentials.get('username')
    password = credentials.get('password')

    # first get the last time
    (mintime, maxtime) = getTimes(current_app.config['SEARCH_TIMEFRAME'],
                                  url, username, password)
    time_string = '"%s"-"%s"' % (mintime, maxtime)
    
    # doesn't appear to be a way to sort order -- it returns oldest to
    # newest and stops at 5000 (limit)
    # we'd prefer newest to oldest
    NW_URL = f'{url}/sdk?msg=msearch&' \
             f'force-content-type=application/json&search={indicator}&where=' \
             f'time={time_string}&limit=1000000&' \
             f'size={current_app.config["MAX_SEARCH_LIMIT"]}&flags=ci,si,sm'

    MAX_VAL = current_app.config['MAX_SEARCH_LIMIT']

    r = requests.get(NW_URL, auth=(username, password))
    json_result = r.json()

    # ensure we got a list back. If we get a dict, it's probably just the one
    # liner response with the scan count
    if isinstance(json_result, list):
        json_count = len(json_result)

        # only display (MAX_VAL) (i.e. 50 records) and don't bother with the
        # last record as its the count usually
        sessions = []
        for x in range(MAX_VAL if json_count >= (MAX_VAL - 1) else json_count):
            sessioninfo = getSessionInfo(
                json_result[x]['results']['id1'], url, username, password) # query the session
            try:
                session = NetwitnessSchema().load(
                    formatSessionInfo(sessioninfo))
                sessions.append(session)
            except ValidationError as err:
                raise InvalidArgumentError(err)
    else:
        sessions = []

    return sessions


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(data):
    return jsonify({'errors': [data]})


def getLastTime(url, username, password):
    time_result = doNWQuery("select max(time)", url,
                            username, password)
    return datetime.datetime.utcfromtimestamp(
        time_result[0]['results']['fields'][0]['value'])


def getTimes(interval, url, username, password):
    # gets the last time and subtracts whatever
    # time period we want (i.e. 1 hour)
    maxtime = getLastTime(url, username, password)
    mintime = maxtime - datetime.timedelta(hours=interval)
    return (mintime, maxtime)


@catch_errors
def doNWQuery(query, url, username, password, limit=1):
    NW_URL = f'{url}/sdk?msg=query&fo' \
             f'rce-content-type=application/json&query={query}&limit={limit}'

    r = requests.get(NW_URL, auth=(username, password))
    json_result = r.json()
    return json_result


def convertEpochTime(epoch):
    return datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc).isoformat(timespec="milliseconds")


@catch_errors
def getSessionInfo(sessionid, url, username, password):
    session_url = f'{url}/sdk?' \
                  'msg=query&force-content-type=application/json&query=select'\
                  ' packets, did, sessionid, time, ip.src, ip.dst, ip.proto, '\
                  'filename, username, service, alias.host, netname, ' \
                  f'direction, eth.src, eth.dst where sessionid={sessionid}&' \
                  'id1=0&id2=0&size=100000&flags=0'
    r = requests.get(session_url, auth=(username, password))
    json_result = r.json()
    return json_result


def formatSessionInfo(sessioninfo):
    cols = {}
    for field in sessioninfo['results']['fields']:
        type_field = field['type']
        if field['format'] == 32:
            value_field = convertEpochTime(field['value'])
        else:
            value_field = field['value']

        cols[type_field] = value_field

    return cols


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def jsonify_result():
    result = {'data': {}}

    if g.get('status'):
        result['data']['status'] = g.status

    if g.get('sightings'):
        result['data']['sightings'] = format_docs(g.sightings)

    if g.get('errors'):
        result['errors'] = g.errors
        if not result['data']:
            del result['data']

    return jsonify(result)
