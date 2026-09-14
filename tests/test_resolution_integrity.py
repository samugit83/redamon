from graph_db.mixins.resolution_integrity_mixin import ResolutionIntegrityMixin


class _Result:
    def __init__(self, row):
        self._row = row

    def single(self):
        return self._row


class _Session:
    def __init__(self):
        self.query = None
        self.params = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, query, **params):
        self.query = query
        self.params = params
        return _Result({"removed": 2})


class _Driver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class _Client(ResolutionIntegrityMixin):
    def __init__(self, session):
        self.driver = _Driver(session)


def test_resolution_integrity_collapses_parallel_edges_and_keeps_record_type():
    session = _Session()
    stats = {}

    removed = _Client(session)._dedupe_resolution_edges("u1", "p1", stats)

    assert removed == 2
    assert stats["duplicate_resolution_edges_removed"] == 2
    assert "collect(r) AS rels" in session.query
    assert "keep.record_type = coalesce" in session.query
    assert "FOREACH (x IN extras | DELETE x)" in session.query
    assert session.params == {"uid": "u1", "pid": "p1"}


def test_resolution_guard_is_tenant_scoped():
    session = _Session()
    _Client(session)._dedupe_resolution_edges("u1", "p1")

    assert "Subdomain {user_id: $uid, project_id: $pid}" in session.query
    assert "IP {user_id: $uid, project_id: $pid}" in session.query
