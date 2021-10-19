from marshmallow import ValidationError, Schema, fields


def validate_string(value):
    if value == '':
        raise ValidationError('Field may not be blank.')


class ObservableSchema(Schema):
    type = fields.String(
        validate=validate_string,
        required=True,
    )
    value = fields.String(
        validate=validate_string,
        required=True,
    )

class NetwitnessSchema(Schema):
    sessionid = fields.Str(required=True)
    time = fields.DateTime(required=True)
    eth_src = fields.Str(required=False, data_key='eth.src')
    eth_dst = fields.Str(required=False, data_key='eth.dst')
    ip_src = fields.Str(required=False, data_key='ip.src')
    ip_dst = fields.Str(required=False, data_key='ip.dst')
    proto = fields.Str(required=False, data_key='ip.proto')
    service = fields.Str(required=False)
    netname = fields.Str(required=False)
    direction = fields.Str(required=False)
    filename = fields.Str(required=False)
    username = fields.Str(required=False)
    packets = fields.Str(required=False)
    did = fields.Str(required=False)
    domain = fields.Str(required=False, data_key='alias.host')
