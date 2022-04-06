from dataclasses import dataclass
from json import JSONDecodeError
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

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


@dataclass
class OperationData:
    name: str
    operation: str
    variables: Dict[str, str]
    selection_set: Any


class GraphQLAnalysis:
    type = GraphQLObjectType(
        "Type", lambda: {"type": GraphQLField(GraphQLString)}
    )
    schema = GraphQLSchema(type)
    backend = GraphQLCoreBackend()

    def __init__(self, payload: Dict) -> None:
        self.operations = []
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

    def get_operation_defs(self, payload: Dict) -> List[OperationDefinition]:
        gql_query = payload.get("query")
        doc = self.backend.document_from_string(
            schema=self.schema, document_string=gql_query
        )
        return doc.document_ast.definitions

    def extract_selection_set(
        self, selection_set: Union[SelectionSet, Tuple], result: List
    ) -> List:
        if isinstance(selection_set, SelectionSet):
            result_part = []
            for field in selection_set.selections:
                result_part.append(field.name.value)
                self.extract_selection_set(field.selection_set, result_part)
            result.append(result_part)
        return result

    def extract_variables(
        self, variable_definitions: List[VariableDefinition]
    ) -> Dict:
        variables = {}
        if not variable_definitions:
            return {}
        for var_def in variable_definitions:
            variables[var_def.variable.name.value] = self.deep_extract_type(
                var_def.type
            )
        return variables

    def deep_extract_type(
        self,
        item_type: Union[ListType, NamedType],
        type_str: Optional[str] = "{}",
    ) -> str:
        if isinstance(item_type, ListType):
            return self.deep_extract_type(item_type.type, "[{}]")
        elif isinstance(item_type, NonNullType):
            return type_str.format(item_type.type.name.value)
        else:
            return type_str.format(item_type.name.value)


class GraphQLInjectable(Injectable):
    async def extract(self, request: Request) -> List:
        payload = await self.get_payload(request)
        analyser = GraphQLAnalysis(payload)
        return [op_data.__dict__ for op_data in analyser.operations]

    @staticmethod
    async def get_payload(request):
        try:
            return await request.json()
        except JSONDecodeError:
            return
