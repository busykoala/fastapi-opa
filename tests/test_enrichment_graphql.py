import json

import pytest
from mock import patch

from fastapi_opa.opa.enrichment.graphql_enrichment import GraphQLAnalysis
from tests.test_data.graphql_queries import GQL_TEST_CASES


@pytest.mark.parametrize("test_payload,expected", GQL_TEST_CASES)
def test_query_parsing(test_payload, expected):
    gql_analysis = GraphQLAnalysis(payload=test_payload)

    assert expected == gql_analysis.operations


async def test_gql_injection(gql_injected_client):
    with patch("fastapi_opa.opa.opa_middleware.requests.post") as req:
        payload = GQL_TEST_CASES[0][0]
        await gql_injected_client.get("/", json=payload)

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
        "request_method": "GET",
        "request_path": [""],
    }

    actual_payload = json.loads(req.call_args_list[0][1].get("data")).get(
        "input"
    )
    assert expected_payload == actual_payload
