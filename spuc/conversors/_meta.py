import hashlib
import inspect
import logging
import ipaddress
import validators

from antlr4 import *

from spuc.grammars.stix.STIXPatternLexer import STIXPatternLexer
from spuc.grammars.stix.STIXPatternParser import STIXPatternParser
from spuc.grammars.stix.STIXPatternVisitor import STIXPatternVisitor


class MetaConversor(ParseTreeVisitor):
    """A MetaConversor
    
    All the SPUC visitors will inherit from this meta visitor to 
    implement the translate method.

    Attributes:
        rules (list): The list of conversion rules.
        strict (str): Forces to raise an error if the rule cannot be 
            strictly mapped to the new conversor.
    """
    def __init__(self, strict=True, **kwargs):
        """Constructor

        Args:
            strict (str): Forces to raise an error if the rule cannot be 
                strictly mapped to the new conversor.
        
        Kwargs:
            Additional atributes potentially used by the conversor.
        """
        super().__init__()
        self.strict = strict
        self.rules = []

    def _is_hash(value:str):
        """Check if the value is a cryptographic hash
        
        Static method that performs the verification.

        Args:
            value (str): The value to check.

        Return:
            bool.
        """
        return False

    def _is_domain(value:str):
        """Check if the value is a domain
        
        Static method that performs the verification.

        Args:
            value (str): The value to check.

        Return:
            bool.
        """
        return validators.domain(value)

    def _is_email(value:str):
        """Check if the value is an email address
        
        Static method that performs the verification.

        Args:
            value (str): The value to check.

        Return:
            bool.
        """
        return validators.email(value)

    def _is_ipv4_address(value:str):
        """Check if the value is an IPv4 Address

        Static method that performs the verification.

        Args:
            value (str): The value to check.

        Return:
            bool.
        """
        try: 
            # Check if address is provided as a /32 network address
            net = ipaddress.ip_network(value)
            return net.prefixlen == 32
        except ValueError as _:
            try:
                ipaddress.ip_address(value)
            except ValueError as _:
                return False
        return True

    def _is_ipv4_range(value:str):
        """Check if the value is an IPv4 Range

        Static method that performs the verification.

        Args:
            value (str): The value to check.

        Return:
            bool.
        """
        try: 
            net = ipaddress.ip_network(value)
            return True
        except ValueError as _:
            return False

    def _is_mac_address(value:str):
        """Check if the value is a MAC address
        
        Static method that performs the verification.

        Args:
            value (str): The value to check.

        Return:
            bool.
        """
        return validators.mac_address(value)

    def _is_url(value:str):
        """Check if the value is a URL address
        
        Static method that performs the verification.

        Args:
            value (str): The value to check.

        Return:
            bool.
        """
        return validators.url(value)

    def _is_uuid(value:str):
        """Check if the value is a UUID address
        
        Static method that performs the verification.

        Args:
            value (str): The value to check.

        Return:
            bool.
        """
        return validators.uuid(value)

    def _prepare(self):
        """Sanitises the rule to prepare for delivery
        
        Returns:
            str. A production-ready rule.
        """
        return self.rules

    def translate(self, stix_pattern:str):
        """Translates a STIX Pattern

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
        output = self.visit(tree)
        return output

    # Visit a parse tree produced by STIXPatternParser#pattern.
    def visitPattern(self, ctx:STIXPatternParser.PatternContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        return self.visit(ctx.observationExpressions())

    # Visit a parse tree produced by STIXPatternParser#observationExpressions.
    def visitObservationExpressions(self, ctx:STIXPatternParser.ObservationExpressionsContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#observationExpressionOr.
    def visitObservationExpressionOr(self, ctx:STIXPatternParser.ObservationExpressionOrContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#observationExpressionAnd.
    def visitObservationExpressionAnd(self, ctx:STIXPatternParser.ObservationExpressionAndContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#observationExpressionRepeated.
    def visitObservationExpressionRepeated(self, ctx:STIXPatternParser.ObservationExpressionRepeatedContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#observationExpressionSimple.
    def visitObservationExpressionSimple(self, ctx:STIXPatternParser.ObservationExpressionSimpleContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#observationExpressionCompound.
    def visitObservationExpressionCompound(self, ctx:STIXPatternParser.ObservationExpressionCompoundContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#observationExpressionWithin.
    def visitObservationExpressionWithin(self, ctx:STIXPatternParser.ObservationExpressionWithinContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#observationExpressionStartStop.
    def visitObservationExpressionStartStop(self, ctx:STIXPatternParser.ObservationExpressionStartStopContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#comparisonExpression.
    def visitComparisonExpression(self, ctx:STIXPatternParser.ComparisonExpressionContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#comparisonExpressionAnd.
    def visitComparisonExpressionAnd(self, ctx:STIXPatternParser.ComparisonExpressionAndContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#propTestEqual.
    def visitPropTestEqual(self, ctx:STIXPatternParser.PropTestEqualContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#propTestOrder.
    def visitPropTestOrder(self, ctx:STIXPatternParser.PropTestOrderContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#propTestSet.
    def visitPropTestSet(self, ctx:STIXPatternParser.PropTestSetContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#propTestLike.
    def visitPropTestLike(self, ctx:STIXPatternParser.PropTestLikeContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#propTestRegex.
    def visitPropTestRegex(self, ctx:STIXPatternParser.PropTestRegexContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#propTestIsSubset.
    def visitPropTestIsSubset(self, ctx:STIXPatternParser.PropTestIsSubsetContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#propTestIsSuperset.
    def visitPropTestIsSuperset(self, ctx:STIXPatternParser.PropTestIsSupersetContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#propTestParen.
    def visitPropTestParen(self, ctx:STIXPatternParser.PropTestParenContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#propTestExists.
    def visitPropTestExists(self, ctx:STIXPatternParser.PropTestExistsContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#startStopQualifier.
    def visitStartStopQualifier(self, ctx:STIXPatternParser.StartStopQualifierContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#withinQualifier.
    def visitWithinQualifier(self, ctx:STIXPatternParser.WithinQualifierContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#repeatedQualifier.
    def visitRepeatedQualifier(self, ctx:STIXPatternParser.RepeatedQualifierContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#objectPath.
    def visitObjectPath(self, ctx:STIXPatternParser.ObjectPathContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#objectType.
    def visitObjectType(self, ctx:STIXPatternParser.ObjectTypeContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#firstPathComponent.
    def visitFirstPathComponent(self, ctx:STIXPatternParser.FirstPathComponentContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#indexPathStep.
    def visitIndexPathStep(self, ctx:STIXPatternParser.IndexPathStepContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#pathStep.
    def visitPathStep(self, ctx:STIXPatternParser.PathStepContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#keyPathStep.
    def visitKeyPathStep(self, ctx:STIXPatternParser.KeyPathStepContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#setLiteral.
    def visitSetLiteral(self, ctx:STIXPatternParser.SetLiteralContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#primitiveLiteral.
    def visitPrimitiveLiteral(self, ctx:STIXPatternParser.PrimitiveLiteralContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        return self.visit(ctx.getChild(0))

    # Visit a parse tree produced by STIXPatternParser#orderableLiteral.
    def visitOrderableLiteral(self, ctx:STIXPatternParser.OrderableLiteralContext):
        """Visit orderable literals 

        Available literals are according to the grammar:
        orderableLiteral
            : IntPosLiteral
            | IntNegLiteral
            | FloatPosLiteral
            | FloatNegLiteral
            | StringLiteral
            | BinaryLiteral
            | HexLiteral
            | TimestampLiteral
            ;

        Return:
            value. The value of the literal child.
        """
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        return str(ctx.getChild(0))