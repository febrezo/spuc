class SPUCException(Exception):
    """Generic SPUC Exception"""


class QualifierNotValidException(SPUCException):
    """Qualifier Not Valid Exception
    
    The Exception is raised whenever an expression qualifier is not acceptable within the context of the current conversor. Expected values are: START/STOP, REPEATED, WITHIN.
    """
    def __init__(self, cls, expression):
        self.message = f"{cls.__class__.__name__} failed: the expression qualifier '{expression}' is not acceptable for the target conversor"
    
    def __str__(self):
        return str(self.message)

class QualifierNotYetImplementedException(SPUCException):
    """Qualifier Not Yet Implemented
    
    The Exception is raised whenever the observation expression has not yet been implemented but it is expected to be. Expected values are: START/STOP, REPEATED, WITHIN.
    """
    def __init__(self, cls, expression):
        self.message = f"{cls.__class__.__name__} failed: the qualifier '{expression}' is not yet implemented"
    
    def __str__(self):
        return str(self.message)

class ObservationExpressionNotValidException(SPUCException):
    """ObservationExpression Not Valid Exception
    
    The Exception is raised whenever the qualifier is not a valid value within the context of the current conversor. Expected values are: AND, OR, FOLLOWEDBY.
    """
    def __init__(self, cls, expression):
        self.message = f"{cls.__class__.__name__} failed: the qualifier '{expression}' is not acceptable for the target conversor"
    
    def __str__(self):
        return str(self.message)

class ObservationExpressionNotYetImplementedException(SPUCException):
    """ObservationExpression Not Yet Implemented
    
    The Exception is raised whenever the observation expression has not yet been implemented but it is expected to be. Expected values are: AND, OR, FOLLOWEDBY.
    """
    def __init__(self, cls, expression):
        self.message = f"{cls.__class__.__name__} failed: the qualifier '{expression}' is not yet implemented"
    
    def __str__(self):
        return str(self.message)

class ObjectPathNotValidException(SPUCException):
    """ObjectPath Not Valid Exception
    
    The Exception is raised whenever the object path is not a valid value within the context of the current conversor. 
    """
    def __init__(self, cls, object_path):
        self.message = f"{cls.__class__.__name__} failed: the object path '{object_path}' is not acceptable for the target conversor"
    
    def __str__(self):
        return str(self.message)


class LiteralNotValidException(SPUCException):
    """Literal Not Valid Exception 

    The Exception is raised whenever the primitive literal is not a valid value within the context of the current conversor. 
    """
    def __init__(self, cls, literal):
        self.message = f"{cls.__class__.__name__} failed: the literal '{literal}' is not acceptable for the target conversor"
    
    def __str__(self):
        return str(self.message)