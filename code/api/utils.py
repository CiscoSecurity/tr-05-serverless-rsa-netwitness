import requests
import datetime
from requests.auth import HTTPDigestAuth
from requests.sessions import session
from marshmallow import Schema, fields, ValidationError
from flask import request, current_app, jsonify, g
from api.errors import AuthorizationError, InvalidArgumentError
from api.schemas import NetwitnessSchema



def get_json(schema):
    g.observables = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(g.observables)

    if message:
        raise InvalidArgumentError(message)

    return g.observables


def query_sightings(indicator):    
    # first get the last time
    (mintime, maxtime) = getTimes(current_app.config['SEARCH_TIMEFRAME'])
    time_string = '"%s"-"%s"' % (mintime, maxtime)

    # doesn't appear to be a way to sort order -- it returns oldest to newest and stops at 5000 (limit)
    # we'd prefer newest to oldest
    NW_URL = 'http://%s:%s/sdk?msg=msearch&force-content-type=application/json&search=%s&where=time=%s&limit=10000000&size=%s&flags=ci,sm' % (
        current_app.config['IP'], current_app.config['APIPORT'], indicator, time_string, current_app.config['MAX_SEARCH_LIMIT'])
    MAX_VAL = 50

    r = requests.get(NW_URL, auth=(current_app.config['USERNAME'], current_app.config['PASSWORD']))
    json_result = r.json()
    
    # ensure we got a list back.  If we get a dict, it's probably just the one liner response with the scan count
    if isinstance(json_result, list):
        json_count = len(json_result)

        # only display (MAX_VAL) (i.e. 50 records) and don't bother with the last record as its the count usually
        sessions = []
        for x in range((MAX_VAL if json_count >= MAX_VAL else json_count) - 1):
            sessioninfo = getSessionInfo(
                json_result[x]['results']['id1'])  # query the session

            try:
                session = NetwitnessSchema().load(formatSessionInfo(sessioninfo))
                sessions.append(session)
            except ValidationError as err:
                raise InvalidArgumentError(session)
            
    else:
        sessions = []

    return sessions


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(data):
    return jsonify({'errors': [data]})

def getLastTime():
    time_result = doNWQuery("select max(time)")
    return datetime.datetime.utcfromtimestamp(time_result[0]['results']['fields'][0]['value'])


def getTimes(interval):
    # gets the last time and subtracts whatever time period we want (i.e. 1 hour)
    maxtime = getLastTime()
    mintime = maxtime - datetime.timedelta(hours=interval)
    return (mintime, maxtime)


def doNWQuery(query, limit=1):
    NW_URL = 'http://%s:%s/sdk?msg=query&force-content-type=application/json&query=%s&limit=%s' % (
        current_app.config['IP'], current_app.config['APIPORT'], query, limit)
    r = requests.get(NW_URL, auth=(current_app.config['USERNAME'], current_app.config['PASSWORD']))
    json_result = r.json()
    return json_result


def convertEpochTime(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat(timespec="milliseconds")


def getSessionInfo(sessionid):
    session_url = 'http://%s:%s/sdk?msg=query&force-content-type=application/json&query=select packets, did, sessionid, time, ip.src, ip.dst, ip.proto, filename, username, service, alias.host, netname, direction, eth.src, eth.dst where sessionid=%s&id1=0&id2=0&size=100000&flags=0' % (
        current_app.config['IP'], current_app.config['APIPORT'], sessionid)
    r = requests.get(session_url, auth=(current_app.config['USERNAME'], current_app.config['PASSWORD']))
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


def jsonify_data(data):
    return jsonify({'data': data})


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