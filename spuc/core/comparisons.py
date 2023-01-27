from enum import Enum
import json

class ComparisonOperator(Enum):
    EQUAL = 1
    NOT_EQUAL = 2
    GREATER_THAN = 3
    LESS_THAN = 4
    GREATER_OR_EQUAL_THAN = 5
    LESS_OR_EQUAL_THAN = 6
    IN = 7
    LIKE = 8
    MATCHES = 9


class ComparisonExpression:
    """An object that represents a comparison expression

    Attributes:
        object_path (str): The STIX object path.
        operator (str): The STIX operator.
        literal (Object): The Python object.
    """
    def __init__(self, object_path, operator, literal):
        """Constructor 

        Args:
            object_path (str): The STIX object path.
            operator (ComparisonOperator): The STIX operator.
            literal (Object): The Python object.
        """ 
        self.object_path = object_path
        if operator.upper() in ("=", "=="):
            self.operator = ComparisonOperator.EQUAL
        elif operator.upper() in ("!=", "<>"):
            self.operator = ComparisonOperator.NOT_EQUAL
        elif operator.upper() == ">":
            self.operator = ComparisonOperator.GREATER_THAN
        elif operator.upper() == "<":
            self.operator = ComparisonOperator.LESS_THAN
        elif operator.upper() == ">=":
            self.operator = ComparisonOperator.GREATER_OR_EQUAL_THAN
        elif operator.upper() == "<=":
            self.operator = ComparisonOperator.LESS_OR_EQUAL_THAN
        elif operator.upper() == "IN":
            self.operator = ComparisonOperator.IN
        elif operator.upper() == "LIKE":
            self.operator = ComparisonOperator.LIKE
        elif operator.upper() == "MATCHES":
            self.operator = ComparisonOperator.MATCHES
        self.literal = literal
    
    def __str__(self):
        return str(self.__dict__)