import inspect
import logging
import random

from spuc.exceptions import ObservationExpressionNotValidException, LiteralNotValidException, ObjectPathNotValidException, QualifierNotValidException
from spuc.exceptions import ObservationExpressionNotYetImplementedException, QualifierNotYetImplementedException
from spuc.conversors._meta import MetaConversor
# from spuc.grammars.stix.STIXPatternLexer import STIXPatternLexer
from spuc.grammars.stix.STIXPatternParser import STIXPatternParser
# from spuc.grammars.stix.STIXPatternVisitor import STIXPatternVisitor

class KQLConversor(MetaConversor):
    """STIX Pattern to KQL Conversor Class

    Any translation operation MUST be performed by reimplementing the 
    appropriate inherited method from `MetaConversor` and, subsequently, from 
    `STIXPatternVisitor`.

    Attributes:
        rules (list): The list of rules created as strings.
    """
    ALLOWED_OBJECT_PATHS = [
        "ipv4-addr:value",
        "ipv6-addr:value",
        "network-traffic:src_ref.type",
        "network-traffic:src_ref.value"
        "network-traffic:src_port.value",
        # "network-traffic:src_payload_ref.value",
        "network-traffic:dst_ref.type",
        "network-traffic:dst_ref.value",
        "network-traffic:dst_port.value",
        # "network-traffic:dst_payload_ref.value",
        "protocols"
    ]
    TEMPLATE = 'DeviceNetworkEvents | where <RULE>'

    def _prepare(self):
        """Sanitises the rule to prepare for delivery
        
        Returns:
            str. A production-ready rule.
        """
        for i, r in enumerate(self.rules):
            r = self.TEMPLATE.replace("<RULE>", r)
            self.rules[i] = r
        return self.rules

    # Visit a parse tree produced by STIXPatternParser#observationExpressions.
    def visitObservationExpressions(self, ctx:STIXPatternParser.ObservationExpressionsContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        if ctx.getChildCount() > 1:
            if self.strict:
                raise ObservationExpressionNotValidException(self, "FOLLOWEDBY")
            else:
                for observationExpressionOr in ctx.observationExpressionOr():
                    self.visit(observationExpressionOr())
        else:
            self.visit(ctx.observationExpressionOr())
        return self._prepare()

    # Visit a parse tree produced by STIXPatternParser#propTestEqual.
    def visitPropTestEqual(self, ctx:STIXPatternParser.PropTestEqualContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        obj = ctx.objectPath().getText()
        ope = ctx.children[1].getText()
        lit = self.visit(ctx.primitiveLiteral())
        logging.debug(f"Equal comparison check: {ctx.getText()}")
        logging.debug(f"\t- Object Path: {obj}")
        logging.debug(f"\t- Operation: {ope}")
        logging.debug(f"\t- Primitive Literal: {lit}")

        if obj not in self.ALLOWED_OBJECT_PATHS:
            raise ObjectPathNotValidException(self, obj)
        else:
            if obj in ["ipv4-addr:value", "ipv6-addr:value"]:
                clean_ip = lit.replace("'", "").replace("/32", "")
                self.rules.append(f'LocalIP == "{clean_ip}" OR RemoteIP == "{clean_ip}"')

    # Visit a parse tree produced by STIXPatternParser#startStopQualifier.
    def visitStartStopQualifier(self, ctx:STIXPatternParser.StartStopQualifierContext):
        logging.warning(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        raise QualifierNotValidException(self, "START/STOP")

    # Visit a parse tree produced by STIXPatternParser#withinQualifier.
    def visitWithinQualifier(self, ctx:STIXPatternParser.WithinQualifierContext):
        logging.warning(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        raise QualifierNotValidException(self, "WITHIN")

    # Visit a parse tree produced by STIXPatternParser#repeatedQualifier.
    def visitRepeatedQualifier(self, ctx:STIXPatternParser.RepeatedQualifierContext):
        logging.warning(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        raise QualifierNotValidException(self, "REPEATED")
