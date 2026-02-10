# Dump the enum defs from the official docs page for a set API version.
# Writes compressed output to ../crystalre/data/cr_funcs.json.zlib
# Script is quite slow, there's 700+ types the scraper has to check

from lxml import etree # pip install lxml
import requests # pip install requests
from tqdm import tqdm # pip install tqdm
import json
from pathlib import Path
import re
import zlib

script_dir = Path(__file__).parent

API_VERSION = "1.19.1"
URL = f"https://crystal-lang.org/api/{API_VERSION}/"

r = requests.get(URL)
r.raise_for_status()

def dump_from_li(li: list, parent_names: list[str]):
    type_links = []
    for cr_type in li:
        cls = cr_type.get("class")
        child_a = cr_type.find('a')
        name = child_a.text
        new_parent_list = [*parent_names, name]
        type_links.append(("::".join(new_parent_list), f"{URL}{child_a.get('href')}"))
        if cls.startswith("parent"):
            li_tags = cr_type.xpath('./ul/li')
            type_links.extend(dump_from_li(li_tags, new_parent_list))
    
    return type_links

base_content = r.text
base_tree = etree.HTML(base_content)
types_list = base_tree.xpath('//div[@class="sidebar"]/div[@class="types-list"]/ul/li')

size_suffixes = sum(
    [[f"u{sz}", f"i{sz}"] for sz in [8, 16, 32, 64]],
    []
)

result_enums = {}
for name, link in tqdm(dump_from_li(types_list, [])):
    r = requests.get(link)
    r.raise_for_status()
    
    obj_content = r.text
    obj_tree = etree.HTML(obj_content)
    
    kind_lst = obj_tree.xpath('//div[@class="main-content"]/h1[@class="type-name"]/span[@class="kind"]/text()')
    if not kind_lst or kind_lst[0].strip() != "enum":
        continue
        
    # print(name, link)
    h2 = obj_tree.xpath('//h2[a[@id="enum-members"]]')[0]
    dt_tags = h2.xpath('./following-sibling::dl[1]//dt[@class="entry-const"]')

    # the enum values are contained in the dt tags
    enum_data = []
    size = "i32"
    for tag in dt_tags:
        enum_name = tag.xpath("./strong/text()")[0]
        enum_value = tag.xpath("./code/span/text()")[0]
        
        if not all(map(str.isdigit, enum_value)):
            enum_value, _, size = enum_value.partition("_")

        # sometimes values are defined at something like `0_u16`, so just capture the string until non-digit
        enum_value = int(re.match(r"\d+", enum_value).group())
        # print((enum_name, enum_value))
        enum_data.append((enum_name, enum_value))

    result_enums[name] = (size, enum_data)


with open(script_dir.parent / "crystalre/data/cr_enums.json.zlib", "wb") as f:
    result = json.dumps(result_enums, separators=(",", ":"))
    compressed = zlib.compress(result.encode("utf-8"), level=9, wbits=-15)
    f.write(compressed)
    print(f"Number of enums scraped: {len(result_enums)}")
    print(f"Uncompressed json size: {len(result):#x}")
    print(f"Compressed json size: {len(compressed):#x}")