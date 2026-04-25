import logging
from dataclasses import dataclass
from json import JSONDecodeError

from graphql import GraphQLCoreBackend
from graphql import GraphQLField
from graphql import GraphQLObjectType
from graphql import GraphQLSchema
from graphql import GraphQLString
from graphql.language.ast import ListType
from graphql.language.ast import NamedType
from graphql.language.ast import NonNullType
from graphql.language.ast import OperationDefinition
from graphql.language.ast import SelectionSet
from graphql.language.ast import VariableDefinition
from starlette.requests import Request

from fastapi_opa.opa.opa_config import Injectable

logger = logging.getLogger(__name__)


@dataclass
class OperationData:
    name: str
    operation: str
    variables: dict[str, str]
    selection_set: list[object]


class GraphQLAnalysis:
    type = GraphQLObjectType(
        "Type", lambda: {"type": GraphQLField(GraphQLString)}
    )
    schema = GraphQLSchema(type)
    backend = GraphQLCoreBackend()

    def __init__(self, payload: dict[str, object] | None) -> None:
        self.operations: list[OperationData] = []
        operation_defs = self.get_operation_defs(payload)
        for operation_def in operation_defs:
            self.operations.append(
                OperationData(
                    name=(
                        operation_def.name.value if operation_def.name else ""
                    ),
                    operation=operation_def.operation,
                    variables=self.extract_variables(
                        operation_def.variable_definitions
                    ),
                    selection_set=self.extract_selection_set(
                        operation_def.selection_set, []
                    ),
                )
            )

    def get_operation_defs(
        self, payload: dict[str, object] | None
    ) -> list[OperationDefinition]:
        if payload is None:
            return []
        gql_query = payload.get("query")
        if not isinstance(gql_query, str):
            return []
        doc = self.backend.document_from_string(
            schema=self.schema, document_string=gql_query
        )
        definitions = doc.document_ast.definitions
        return [
            definition
            for definition in definitions
            if isinstance(definition, OperationDefinition)
        ]

    def extract_selection_set(
        self,
        selection_set: SelectionSet | tuple[object, ...] | None,
        result: list[object],
    ) -> list[object]:
        if isinstance(selection_set, SelectionSet):
            result_part: list[object] = []
            for field in selection_set.selections:
                result_part.append(field.name.value)
                self.extract_selection_set(field.selection_set, result_part)
            result.append(result_part)
        return result

    def extract_variables(
        self, variable_definitions: list[VariableDefinition] | None
    ) -> dict[str, str]:
        variables: dict[str, str] = {}
        if not variable_definitions:
            return {}
        for var_def in variable_definitions:
            variables[var_def.variable.name.value] = self.deep_extract_type(
                var_def.type
            )
        return variables

    def deep_extract_type(
        self,
        item_type: ListType | NamedType | NonNullType,
        type_str: str = "{}",
    ) -> str:
        if isinstance(item_type, ListType):
            return self.deep_extract_type(item_type.type, "[{}]")
        if isinstance(item_type, NonNullType):
            return self.deep_extract_type(item_type.type, type_str)
        return type_str.format(item_type.name.value)


class GraphQLInjectable(Injectable):
    async def extract(self, request: Request) -> list[object]:
        payload = await self.get_payload(request)
        analyser = GraphQLAnalysis(payload)
        return [
            {
                "name": op_data.name,
                "operation": op_data.operation,
                "variables": op_data.variables,
                "selection_set": op_data.selection_set,
            }
            for op_data in analyser.operations
        ]

    @staticmethod
    async def get_payload(request: Request) -> dict[str, object] | None:
        try:
            payload = await request.json()
        except JSONDecodeError:
            logger.debug("Failed to parse request body as JSON")
            return None
        return payload if isinstance(payload, dict) else None
