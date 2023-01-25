from antlr4 import *

from spuc.conversors._meta import MetaConversor
from spuc.grammars.stix.STIXPatternLexer import STIXPatternLexer
from spuc.grammars.stix.STIXPatternParser import STIXPatternParser
from spuc.grammars.stix.STIXPatternVisitor import STIXPatternVisitor

class STIX2YaraConversor(MetaConversor, STIXPatternVisitor):
    """STIX Pattern to Yara Conversor Class

    It contains a static `translate` method that grabs a text and
    tries to parse it using STIXPattern. 
    Note that this class inherits from the ANTLR-generated `STIXPatternVisitor`. 
    Any translation operation MUST be performed by reimplementing the 
    appropriate inherited method from `STIXPatternVisitor`.

    `antlr4` imports as well as the grammar files SHOULD be imported.
    """
    # Visit a parse tree produced by STIXPatternParser#pattern.
    def visitPattern(self, ctx:STIXPatternParser.PatternContext):
        return "Parsing process ended."

    def translate(stix_pattern:str):
        """Translates a STIX Pattern

        Static method invoked to make the conversion.

        Args:
            stix_pattern (str): The STIX Pattern to translate.

        Returns:
            str. The translated pattern.

        Raises:
            ValueError. Whenever the provided string cannot be translated
                to the current conversor rules.
        """
        data =  InputStream(stix_pattern)
        # lexer
        lexer = STIXPatternLexer(data)
        stream = CommonTokenStream(lexer)
        # parser
        parser = STIXPatternParser(stream)
        tree = parser.pattern()
        # evaluator
        visitor = STIX2YaraConversor()
        output = visitor.visit(tree)
        return output
