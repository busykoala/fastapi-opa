import logging
from dataclasses import dataclass
from json import JSONDecodeError

from graphql import GraphQLError
from graphql import parse
from graphql.language.ast import FieldNode
from graphql.language.ast import ListTypeNode
from graphql.language.ast import NamedTypeNode
from graphql.language.ast import NonNullTypeNode
from graphql.language.ast import OperationDefinitionNode
from graphql.language.ast import SelectionSetNode
from graphql.language.ast import TypeNode
from graphql.language.ast import VariableDefinitionNode
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
    def __init__(self, payload: dict[str, object] | None) -> None:
        self.operations: list[OperationData] = []
        operation_defs = self.get_operation_defs(payload)
        for operation_def in operation_defs:
            self.operations.append(
                OperationData(
                    name=(
                        operation_def.name.value if operation_def.name else ""
                    ),
                    operation=operation_def.operation.value,
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
    ) -> list[OperationDefinitionNode]:
        if payload is None:
            return []
        gql_query = payload.get("query")
        if not isinstance(gql_query, str):
            return []
        try:
            doc = parse(gql_query)
        except GraphQLError:
            logger.warning("Failed to parse GraphQL query: invalid syntax")
            return []
        definitions = doc.definitions
        return [
            definition
            for definition in definitions
            if isinstance(definition, OperationDefinitionNode)
        ]

    def extract_selection_set(
        self,
        selection_set: SelectionSetNode | None,
        result: list[object],
    ) -> list[object]:
        if isinstance(selection_set, SelectionSetNode):
            result_part: list[object] = []
            for field in selection_set.selections:
                if not isinstance(field, FieldNode):
                    continue
                result_part.append(field.name.value)
                self.extract_selection_set(field.selection_set, result_part)
            result.append(result_part)
        return result

    def extract_variables(
        self, variable_definitions: tuple[VariableDefinitionNode, ...] | None
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
        item_type: TypeNode,
        type_str: str = "{}",
    ) -> str:
        if isinstance(item_type, ListTypeNode):
            return self.deep_extract_type(item_type.type, "[{}]")
        if isinstance(item_type, NonNullTypeNode):
            return self.deep_extract_type(item_type.type, type_str)
        if not isinstance(item_type, NamedTypeNode):
            raise TypeError("Unsupported GraphQL type node")
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
