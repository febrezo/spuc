def get_username():
    from pwd import getpwuid
    from os import getuid
    return getpwuid(getuid())[ 0 ]

def get_factorial(x):
    """Calculate the factorial of a number

    This is a recursive function to find the factorial of an integer
    
    Args: 
        x (int): The number to calculate the factorial.

    Returns:
        int. The factorial.
    """
    x = int(x)
    if x == 1:
        return 1
    else:
        # recursive call to the function
        return (x * get_factorial(x-1))

def translate(stix_pattern:str, conversors):
    """Translates a STIX Pattern to a conversor

    Returns:
        list. A list of created rules
    """