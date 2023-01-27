import unittest

from spuc.conversors.snort import SnortConversor
from spuc.exceptions import *

from ._examples import *

class TestSnortConversor(unittest.TestCase):
    def setUp(self):
        self.conversor = SnortConversor()

    def test_expr_ipv4_equals(self):
        value = self.conversor.translate(EXPRESSION_IPV4_EQUAL_VALUE)
        expected_value = [
            'alert any 1.1.1.1/32 any > any any (msg: "Generic Snort rule created by SPUC"; sid: 3000000; rev: 1;)', 
            'alert any any any > 1.1.1.1/32 any (msg: "Generic Snort rule created by SPUC"; sid: 3000001; rev: 1;)'
        ]

        self.assertListEqual(
            expected_value,
            value
        )

    def test_expr_ipv4_without_subnet_equals(self):
        value = self.conversor.translate(EXPRESSION_IPV4_EQUAL_VALUE_WITHOUT_SUBNET)
        expected_value = [
            'alert any 1.1.1.1 any > any any (msg: "Generic Snort rule created by SPUC"; sid: 3000000; rev: 1;)', 
            'alert any any any > 1.1.1.1 any (msg: "Generic Snort rule created by SPUC"; sid: 3000001; rev: 1;)'
        ]

        self.assertListEqual(
            expected_value,
            value
        )

    def test_expr_filename(self):
        with self.assertRaises(ObjectPathNotValidException):
            self.conversor.translate(FILENAME_OBSERVABLE)


if __name__ == '__main__':
    unittest.main()
