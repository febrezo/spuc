import inspect
import json
import logging
import random

from spuc.exceptions import ObservationExpressionNotValidException, LiteralNotValidException, ObjectPathNotValidException, QualifierNotValidException
from spuc.exceptions import ObservationExpressionNotYetImplementedException, QualifierNotYetImplementedException
from spuc.conversors._meta import MetaConversor
from spuc.grammars.stix.STIXPatternParser import STIXPatternParser
from spuc.core import ComparisonExpression
from spuc.core import ComparisonOperator

class SnortConversor(MetaConversor):
    """STIX Pattern to Snort Conversor Class

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
        "network-traffic:src_ref.value",
        "network-traffic:src_port",
        # "network-traffic:src_payload_ref.value",
        "network-traffic:dst_ref.type",
        "network-traffic:dst_ref.value",
        "network-traffic:dst_port",
        # "network-traffic:dst_payload_ref.value",
        "network-traffic:protocols[*]"
    ]
    TEMPLATE = 'alert <PROTOCOL> <SRC_IP_RANGE> <SRC_PORT> > <DST_IP_RANGE> <DST_PORT> (msg: "<MESSAGE>"; sid: <SID>; rev: 1;)'

    def _prepare(self):
        """Sanitises the rule to prepare for delivery
        
        Returns:
            str. A production-ready rule.
        """
        for i, r in enumerate(self.rules):
            r = r.replace("<PROTOCOL>", "any")
            r = r.replace("<SRC_IP_RANGE>", "any")
            r = r.replace("<SRC_PORT>", "any")
            r = r.replace("<DST_IP_RANGE>", "any")
            r = r.replace("<DST_PORT>", "any")
            r = r.replace("<MESSAGE>", "Generic Snort rule created by SPUC")
            r = r.replace("<SID>", str(3000000+ i))
            self.rules[i] = r
        return self.rules

    def _build_comparisons(self, comparisons):
        """Build the comparisons

        This method implements the API to build the comparison strings for
        each wrapper. The comparisons refer to a single observation expression.
        This method WILL be reimplemented in every conversor creating specific
        logics for each transformation.

        Args:
            comparisons (list): A list of comparisons to be creted
        """
        logging.debug(f"Processing {len(comparisons)} comparisons…")
        for i, comp in enumerate(comparisons):
            if comp.object_path in ["ipv4-addr:value", "ipv6-addr:value"]:
                self.rules.append(
                    self.TEMPLATE.replace("<SRC_IP_RANGE>", comp.literal.replace("'", ""))
                )
            if comp.object_path in ["ipv4-addr:value", "ipv6-addr:value"]:
                self.rules.append(
                    self.TEMPLATE.replace("<DST_IP_RANGE>", comp.literal.replace("'", ""))
                )

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

    # Visit a parse tree produced by STIXPatternParser#observationExpressionOr.
    def visitObservationExpressionOr(self, ctx:STIXPatternParser.ObservationExpressionOrContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        self.visitChildren(ctx)

    # Visit a parse tree produced by STIXPatternParser#observationExpressionAnd.
    def visitObservationExpressionAnd(self, ctx:STIXPatternParser.ObservationExpressionAndContext):
        logging.debug(f"{inspect.currentframe().f_code.co_name} @ '{inspect.currentframe().f_code.co_filename}'. Expression: \"{ctx.getText()}\"")
        # AND ObservationExpressions are rejected because cannot be mapped 
        #   onto a single SNORT rule
        if self.strict and ctx.getChildCount() > 1:
            raise ObservationExpressionNotValidException(self, "AND")
        else:
            self.visitChildren(ctx)

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
