class StixRelayError(Exception):
    code = "internal_error"
    status = 500


class ValidationError(StixRelayError):
    code = "validation_error"
    status = 400


class NotFoundError(StixRelayError):
    code = "not_found"
    status = 404


class ConflictError(StixRelayError):
    code = "conflict"
    status = 409
