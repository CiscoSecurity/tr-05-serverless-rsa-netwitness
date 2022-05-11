from uuid import uuid4
from flask import current_app, g


class Mapping:
    @staticmethod
    def formatTime(datestamp):
        return datestamp
        # return datestamp.isoformat(timespec="milliseconds")

    def observed_time(self, event):
        event_time = self.formatTime(event['time'])
        return {
            'start_time': event_time,
            'end_time': event_time
        }

    @staticmethod
    def get_relations(event):
        if ((event.get("ip_src") and event.get("ip_dst")) and
                (event["ip_src"] != event["ip_dst"])):
            return [
                {
                    "related": {
                        "type": "ip",
                        "value": event['ip_dst']
                    },
                    "source": {
                        "type": "ip",
                        "value": event["ip_src"]
                    },
                    **current_app.config['RELATIONS_DEFAULTS']
                }
            ]
        else:
            return []

    def observables(self, event):
        return g.observables

    def targets(self, event):
        observables = []

        if event.get('ip_dst'):
            observables.append({'type': 'ip',
                                'value': event['ip_dst']})
        if event.get('filename'):
            observables.append({'type': 'file_name',
                                'value': event['filename']})
        if event.get('eth_dst'):
            observables.append({'type': 'mac_address',
                                'value': event['eth_dst']})
        if event.get('username'):
            observables.append({'type': 'user',
                                'value': event['username']})
        if event.get('hostname'):
            observables.append({'type': 'hostname',
                                'value': event['hostname']})

        if not observables:
            return []

        target = {
            'observables': observables,
            'observed_time': self.observed_time(event),
            'type': 'endpoint',
        }

        return [target]

    def sighting(self, observable, event):
        if event.get('packets'):
            count = event['packets']
        else:
            count = 1

        link_keys = ["ip.src", "ip.dst", "alias.host"]
        mapping_str = []
        for item in event:
            if item in link_keys:
                mapping_str.append(
                    "{}: [{}](/investigate?q={})\n".format(item, event[item], event[item]))
            else:
                mapping_str.append("{}: {}\n".format(item, event[item]))

        metadata = "- ".join(mapping_str)

        d = {
            'id': f'sighting-{uuid4()}',
            'targets': self.targets(event),
            'relations': self.get_relations(event),
            'count': int(count),
            'observed_time': self.observed_time(event),
            'observables': self.observables(event),
            'short_description':
                f"RSA Netwitness session ID {event['sessionid']} ({event['netname']})",
            'description': 'RSA Netwitness session ID '
                           f'{event["sessionid"]} retrieved from decoder '
                           f'{event["did"]} related to '
                           f'{observable["value"]}'
                           f'\n\nNetWitness Mapped Values:\n- {metadata}\n\n',
            **current_app.config['SIGHTING_DEFAULTS']
        }

        return d
