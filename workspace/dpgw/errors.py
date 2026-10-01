"""Typed errors with stable error codes and HTTP statuses."""

from __future__ import annotations


class DPGWError(Exception):
    """All gateway errors carry a stable machine code and HTTP status."""

    code = "internal_error"
    status = 500
    action = None  # recorded in audit log when set

    def __init__(self, message: str = "", *, action: str | None = None, **extra):
        super().__init__(message or self.code)
        self.message = message or self.code
        if action is not None:
            self.action = action
        self.extra = extra

    def to_dict(self) -> dict:
        d = {"error": self.code, "message": self.message}
        d.update(self.extra)
        return d


class InvalidQuery(DPGWError):
    code = "invalid_query"
    status = 400


class InvalidBody(DPGWError):
    code = "invalid_body"
    status = 400


class InvalidSnapshot(DPGWError):
    code = "invalid_snapshot"
    status = 400


class SnapshotNotFound(DPGWError):
    code = "snapshot_not_found"
    status = 404


class SnapshotInactive(DPGWError):
    code = "snapshot_inactive"
    status = 409


class SnapshotAlreadyExists(DPGWError):
    code = "snapshot_already_exists"
    status = 409


class TeamNotFound(DPGWError):
    code = "team_not_found"
    status = 404


class TeamAlreadyExists(DPGWError):
    code = "team_already_exists"
    status = 409


class BudgetExceeded(DPGWError):
    code = "budget_exceeded"
    status = 409
    action = "reject_budget"


class BudgetInvalid(DPGWError):
    code = "budget_invalid"
    status = 400


class FrozenQuery(DPGWError):
    code = "query_family_frozen"
    status = 403
    action = "reject_frozen"


class ResultNotFound(DPGWError):
    code = "result_not_found"
    status = 404


class Unauthorized(DPGWError):
    code = "unauthorized"
    status = 401


class Forbidden(DPGWError):
    code = "forbidden"
    status = 403


class Conflict(DPGWError):
    code = "conflict"
    status = 409


class JobNotFound(DPGWError):
    code = "job_not_found"
    status = 404


class JobConflict(DPGWError):
    """Same request_key reused for a different job payload."""

    code = "job_conflict"
    status = 409


class JobTicketExpired(DPGWError):
    code = "job_ticket_expired"
    status = 410


class JobStateConflict(DPGWError):
    """The requested transition is illegal from the job's current state."""

    code = "job_state_conflict"
    status = 409


class JobInvalid(DPGWError):
    code = "job_invalid"
    status = 400


# --------------------------------------------------------------------------- #
# amendable joint publication batches
# --------------------------------------------------------------------------- #

class PublicationNotFound(DPGWError):
    code = "publication_not_found"
    status = 404


class PublicationInvalid(DPGWError):
    code = "publication_invalid"
    status = 400


class PublicationStateConflict(DPGWError):
    """Illegal transition for a batch/version (already sealed, not collecting...)."""

    code = "publication_state_conflict"
    status = 409


class PublicationClosed(PublicationStateConflict):
    """The books are closed (deadline passed / sealed): contribution is too late."""

    code = "publication_closed"
    status = 410


class NotParticipating(PublicationStateConflict):
    """Withdrawal (or an idempotent replay target) requires an active contribution."""

    code = "not_participating"
    status = 409


class QuorumNotMet(PublicationStateConflict):
    """Sealing was attempted with fewer distinct teams than min_participants."""

    code = "quorum_not_met"
    status = 409


class SpecificationChanged(PublicationInvalid):
    """A revision must reuse the exact fixed statistical specification."""

    code = "specification_changed"
    status = 409


# --------------------------------------------------------------------------- #
# controlled sharing packages (field-trimmed release redistributions)
# --------------------------------------------------------------------------- #

class ShareNotFound(DPGWError):
    code = "share_not_found"
    status = 404


class ShareInvalid(DPGWError):
    code = "share_invalid"
    status = 400


class ShareForbidden(DPGWError):
    """The team is not in the release audience or a field is outside its grant."""

    code = "share_forbidden"
    status = 403


class ShareStateConflict(DPGWError):
    """Illegal transition for a sharing package (e.g. revoke a non-sealed one)."""

    code = "share_state_conflict"
    status = 409


class ShareRevoked(DPGWError):
    code = "share_revoked"
    status = 410


class ShareExpired(DPGWError):
    code = "share_expired"
    status = 410


# --------------------------------------------------------------------------- #
# anti-fork transparency ledger
# --------------------------------------------------------------------------- #

class TransparencyFrozen(DPGWError):
    """The transparency log is frozen after fork evidence; no new leaves may be
    issued (seal/void/share-issue/revoke all fail explicitly)."""

    code = "transparency_frozen"
    status = 423


class TransparencyConflict(DPGWError):
    """An event_key was reused with a different payload (replay conflict)."""

    code = "transparency_conflict"
    status = 409


class TransparencyNotFound(DPGWError):
    code = "transparency_not_found"
    status = 404


class TransparencyCheckpointExpired(DPGWError):
    """A proof/checkpoint lookup asks for a tree size past the latest checkpoint."""

    code = "checkpoint_expired"
    status = 410


class TransparencyProofInvalid(DPGWError):
    """A fork-evidence submission or proof document fails verification."""

    code = "transparency_proof_invalid"
    status = 400
