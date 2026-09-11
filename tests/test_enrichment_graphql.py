import pytest

from fastapi_opa.opa.enrichment.graphql_enrichment import GraphQLAnalysis
from tests.test_data.graphql_queries import GQL_TEST_CASES


@pytest.mark.parametrize(("test_payload", "expected"), GQL_TEST_CASES)
def test_query_parsing(test_payload, expected):
    gql_analysis = GraphQLAnalysis(payload=test_payload)

    assert expected == gql_analysis.operations


def test_invalid_graphql_query_returns_empty_operations():
    gql_analysis = GraphQLAnalysis(payload={"query": "invalid query !!!"})
    assert gql_analysis.operations == []


@pytest.mark.asyncio
async def test_gql_injection(gql_injected_client, opa_client):
    payload = GQL_TEST_CASES[0][0]
    gql_injected_client.post("/", json=payload)

    expected_payload = {
        "stuff": "some info",
        "username": "John Doe",
        "role": "Administrator",
        "gql_injectable": [
            {
                "name": "getStudents",
                "operation": "query",
                "selection_set": [
                    ["students", ["Student", ["name", "subject", "enrolled"]]]
                ],
                "variables": {"enrolled": "Boolean", "subject": "String"},
            }
        ],
        "request_method": "POST",
        "request_path": [""],
    }

    actual_payload = opa_client.calls[0][1]["input"]
    assert expected_payload == actual_payload
