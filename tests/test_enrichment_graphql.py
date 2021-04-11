import pytest

from fastapi_opa.opa.enrichment.graphql_enrichment import GraphQLAnalysis
from tests.test_data.graphql_queries import GQL_TEST_CASES


@pytest.mark.parametrize("test_payload,expected", GQL_TEST_CASES)
def test_query_parsing(test_payload, expected):
    gql_analysis = GraphQLAnalysis(payload=test_payload)

    assert expected == gql_analysis.operations
