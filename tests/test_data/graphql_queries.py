from fastapi_opa.opa.enrichment.graphql_enrichment import OperationData

GQL_TEST_CASES = [
    (
        {
            "operationName": "getStudents",
            "variables": {"subject": "Physics", "enrolled": True},
            "query": """query getStudents(
                $subject: String,
                $enrolled: Boolean){
                students(
                    subject: $subject,
                    enrolled: $enrolled){
                        Student {
                            name
                            subject
                            enrolled
                        }
                    }
                }
            """,
        },
        [
            OperationData(
                name="getStudents",
                operation="query",
                variables={"subject": "String", "enrolled": "Boolean"},
                selection_set=[
                    ["students", ["Student", ["name", "subject", "enrolled"]]]
                ],
            )
        ],
    ),
    (
        {
            "operationName": "getStudents",
            "variables": {"subject": "Physics", "enrolled": True},
            "query": """query getStudents(
            $subject: String,
            $enrolled: Boolean){
            students(
                subject: $subject,
                enrolled: $enrolled){
                    Student {
                        name
                        subject
                        friends {
                            nickname
                        }
                        enrolled
                    }
                }
            }
        """,
        },
        [
            OperationData(
                name="getStudents",
                operation="query",
                variables={"subject": "String", "enrolled": "Boolean"},
                selection_set=[
                    [
                        "students",
                        [
                            "Student",
                            [
                                "name",
                                "subject",
                                "friends",
                                ["nickname"],
                                "enrolled",
                            ],
                        ],
                    ]
                ],
            )
        ],
    ),
    (
        {
            "operationName": "addStudent",
            "variables": {"name": "Peter", "subject": "Programming"},
            "query": """mutation addStudent(
            $name: String,
            $subject: String){
            student(
                name: $name,
                subject: $subject){
                    Student {
                        name
                        subject
                    }
                }
            }
        """,
        },
        [
            OperationData(
                name="addStudent",
                operation="mutation",
                variables={"name": "String", "subject": "String"},
                selection_set=[["student", ["Student", ["name", "subject"]]]],
            )
        ],
    ),
    (
        {
            "operationName": "addStudent",
            "variables": {
                "name": "Peter",
                "subject": "Programming",
                "friends": ["Anna", "Berta"],
            },
            "query": """mutation addStudent(
            $name: String,
            $subject: String,
            $friends: [String]){
            student(
                name: $name,
                subject: $subject
                friends: $friends){
                    Student {
                        name
                        subject
                        friends
                    }
                }
            }
        """,
        },
        [
            OperationData(
                name="addStudent",
                operation="mutation",
                variables={
                    "name": "String",
                    "subject": "String",
                    "friends": "[String]",
                },
                selection_set=[
                    ["student", ["Student", ["name", "subject", "friends"]]]
                ],
            )
        ],
    ),
]
