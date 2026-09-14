from graph_db.mixins.recon.js_recon_mixin import JsReconMixin
from graph_db.mixins.recon.js_recon_owned_endpoint_mixin import JsReconOwnedEndpointMixin


class _Result:
    def __init__(self, row):
        self._row = row

    def single(self):
        return self._row


class _Session:
    def __init__(self):
        self.queries = []
        self._responses = [
            {"removed": 2},
            {"linked": 5},
        ]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, query, **params):
        self.queries.append((query, params))
        return _Result(self._responses.pop(0))


class _Driver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class _Client(JsReconOwnedEndpointMixin):
    def __init__(self, session):
        self.driver = _Driver(session)


def test_js_recon_endpoint_guard_removes_unowned_and_links_valid(monkeypatch):
    monkeypatch.setattr(
        JsReconMixin,
        "update_graph_from_js_recon",
        lambda self, recon_data, user_id, project_id: {
            "endpoints_created": 7,
            "relationships_created": 3,
            "errors": [],
        },
    )

    session = _Session()
    stats = _Client(session).update_graph_from_js_recon({}, "u1", "p1")

    assert stats["invalid_endpoints_removed"] == 2
    assert stats["endpoint_owners_linked"] == 5
    assert stats["endpoints_created"] == 5

    cleanup_query = session.queries[0][0]
    owner_query = session.queries[1][0]

    assert "e.source = 'js_recon'" in cleanup_query
    assert "coalesce(e.baseurl, '') <> 'upload'" in cleanup_query
    assert "MATCH (:BaseURL" in cleanup_query
    assert "DETACH DELETE" in cleanup_query

    assert "MATCH (bu:BaseURL" in owner_query
    assert "MERGE (bu)-[r:HAS_ENDPOINT]->(e)" in owner_query


def test_uploaded_js_exception_is_explicit_in_guard_source():
    # Uploaded JS has no network BaseURL by design and must remain supported.
    import inspect

    source = inspect.getsource(JsReconOwnedEndpointMixin.update_graph_from_js_recon)
    assert "<> 'upload'" in source
