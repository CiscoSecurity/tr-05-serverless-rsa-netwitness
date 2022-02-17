AUTH_ERROR = 'authorization error'
INVALID_ARGUMENT = 'invalid argument'
UNKNOWN = 'unknown'
CONNECTION_ERROR = 'connection error'


class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class AuthorizationError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            AUTH_ERROR,
            f'Authorization failed: {message}'
        )


class InvalidArgumentError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            INVALID_ARGUMENT,
            str(message)
        )


class RSANetwitnessSSLError(TRFormattedError):
    def __init__(self, error):
        message = getattr(
            error.args[0].reason.args[0], 'verify_message', ''
        ) or error.args[0].reason.args[0].args[0]

        super().__init__(
            UNKNOWN,
            f'Unable to verify SSL certificate: {message}'
        )


class RSANetwitnessConnectionError(TRFormattedError):
    def __init__(self):
        super().__init__(
            CONNECTION_ERROR,
            'Unable to connect to RSA Netwitness,'
            ' validate the configured API endpoint'
        )
