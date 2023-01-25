compile-grammar:
	java -jar ./bin/antlr-4.11.1-complete.jar -Dlanguage=Python3 spuc/grammars/stix/STIXPattern.g4

install:
	make && pip3 install -e . && spuc-cli 

run:
	spuc-cli -c snort kql tql xql -L DEBUG -p "[ipv4-addr:value = '1.1.1.1/32']"

debug:
	python3 -m pdb -c "b spuc/conversors/snort.py:273" spuc/cli.py -c snort -p "[ipv4-addr:value = '1.1.1.1/32']"
