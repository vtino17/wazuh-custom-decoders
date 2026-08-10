from pathlib import Path
import re
from xml.etree import ElementTree


root = ElementTree.parse("rules/0020-mikrotik-rules.xml").getroot()
rules = root.findall("rule")
ids = [rule.attrib["id"] for rule in rules]

assert len(ids) == len(set(ids)), "rule IDs must be unique"
assert ids == ["100001", "100002", "100003", "100004", "100005"]
for rule in rules[1:]:
    assert int(rule.attrib["level"]) > 0
    assert rule.findtext("if_sid") == "100001"
    assert rule.findtext("description")

decoder = ElementTree.parse("decoders/0020-mikrotik-decoder.xml").getroot()
assert decoder.findtext("prematch") == r"^<\d+>"
assert decoder.find("prematch").attrib["type"] == "pcre2"
assert decoder.find("regex").attrib["type"] == "pcre2"
sample = (
    "<14>Jul 21 08:15:00 mikrotik-lan firewall,info DROP: "
    "in:ether1 src-address=192.0.2.10"
)
match = re.match(decoder.findtext("regex"), sample)
assert match
assert match.groups()[:3] == ("14", "Jul 21 08:15:00", "mikrotik-lan")
assert Path("README.md").read_text(encoding="utf-8").count("roadmap items") == 1
