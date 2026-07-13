from schemas import SearchResult
def test_search_result_serialization():
    result = SearchResult(
        id=10,
        sender="alice@example.com",
        subject="Payroll",
        date_raw="2020-01-01",
    )

    data = result.model_dump()

    assert data["id"] == 10
    assert data["sender"] == "alice@example.com"
    assert "body" not in data