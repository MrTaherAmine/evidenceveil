class EvidenceVeilError(Exception):
    """Expected operational error safe to render without a traceback."""


class PolicyError(EvidenceVeilError):
    pass


class InputError(EvidenceVeilError):
    pass


class VaultError(EvidenceVeilError):
    pass


class IntegrityError(EvidenceVeilError):
    pass
