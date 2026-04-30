import json
import re
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from xml.dom import minidom
from xml.etree import ElementTree as ET

import requests
from bs4 import BeautifulSoup
from jsonschema import Draft202012Validator


SOURCE_URL = "https://tomcat.apache.org/security-9.html"
CVE_API = "https://cveawg.mitre.org/api/cve/"
CVE_URL = "https://www.cve.org/CVERecord?id="
CWE_ZIP = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


def save_json(file_name, data):
    with open(file_name, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def read_json(file_name):
    with open(file_name, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_date(value):
    value = value.strip()
    for fmt in ("%Y-%m-%d", "%d %B %Y"):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            pass
    return ""


def get_public_date(p):
    patterns = [
        r"made public on ([^.]+)",
        r"formally announced as\s+a vulnerability on ([^.]+)",
        r"reported publicly on ([^.]+)",
    ]
    for next_p in p.find_next_siblings("p"):
        if next_p.find("strong"):
            break
        text = next_p.get_text(" ", strip=True)
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.I)
            if match:
                return parse_date(match.group(1))
    return ""


def task_1():
    html = requests.get(SOURCE_URL, timeout=30).text
    soup = BeautifulSoup(html, "html.parser")
    result = []
    used = set()

    for h3 in soup.select("h3[id^='Fixed_in_Apache_Tomcat_9']"):
        release_date = parse_date(h3.select_one("span.pull-right").get_text(strip=True))
        url = SOURCE_URL + "#" + h3["id"]
        section = h3.find_next_sibling("div", class_="text")

        for p in section.find_all("p", recursive=False):
            strong = p.find("strong")
            if not strong:
                continue

            cves = []
            for link in p.find_all("a", recursive=False):
                cves += re.findall(r"CVE-\d{4}-\d{4,}", link.get_text(" ") + link.get("href", ""))

            if not cves:
                cves = re.findall(r"CVE-\d{4}-\d{4,}", strong.get_text(" "))

            for cve in sorted(set(cves)):
                cve = cve.upper()
                if cve in used:
                    continue
                used.add(cve)
                result.append({
                    "ID": cve,
                    "vendor_release_date": release_date or get_public_date(p),
                    "vendor_release_url": url,
                })

    save_json("result_task_1.json", result)
    print("task 1:", len(result))


def download_cwe():
    cache = Path("cwec_latest.xml")
    if not cache.exists():
        zip_name = "cwec_latest.xml.zip"
        Path(zip_name).write_bytes(requests.get(CWE_ZIP, timeout=60).content)
        with zipfile.ZipFile(zip_name) as z:
            xml_name = [name for name in z.namelist() if name.endswith(".xml")][0]
            cache.write_bytes(z.read(xml_name))
    return cache


def get_cwe_dict():
    root = ET.parse(download_cwe()).getroot()
    result = {}
    for weakness in root.findall(".//{*}Weakness"):
        cwe_id = "CWE-" + weakness.attrib["ID"]
        result[cwe_id] = {
            "name": weakness.attrib.get("Name", ""),
            "description": weakness.findtext("{*}Description", default=""),
        }
    return result


def get_description(record):
    descriptions = record.get("containers", {}).get("cna", {}).get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return re.sub(r"\s+", " ", item.get("value", "")).strip()
    return ""


def get_cvss(record):
    result = []
    metrics = record.get("containers", {}).get("cna", {}).get("metrics", [])
    for adp in record.get("containers", {}).get("adp", []):
        metrics += adp.get("metrics", [])

    for metric in metrics:
        for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
            if key not in metric:
                continue
            item = metric[key]
            result.append({
                "version": "cvss" + item.get("version", "").replace(".", ""),
                "score": item.get("baseScore"),
                "vector": item.get("vectorString", ""),
                "severity": item.get("baseSeverity", ""),
            })
    return result


def get_cpe(record):
    result = []
    affected = record.get("containers", {}).get("cna", {}).get("affected", [])
    for item in affected:
        result += item.get("cpes", [])
        for version in item.get("versions", []):
            result += version.get("cpes", [])
    return sorted(set(result))


def get_cwe(record, cwe_dict):
    result = {}
    problem_types = record.get("containers", {}).get("cna", {}).get("problemTypes", [])
    for problem_type in problem_types:
        for description in problem_type.get("descriptions", []):
            cwe_id = description.get("cweId")
            if cwe_id and cwe_id.startswith("CWE-"):
                result[cwe_id] = cwe_dict.get(cwe_id, {
                    "name": description.get("description", cwe_id),
                    "description": description.get("description", cwe_id),
                })
    return result


def task_2():
    cwe_dict = get_cwe_dict()
    result = []

    for row in read_json("result_task_1.json"):
        for i in range(3):
            try:
                record = requests.get(CVE_API + row["ID"], timeout=30).json()
                break
            except requests.RequestException:
                if i == 2:
                    raise

        result.append({
            **row,
            "url": CVE_URL + row["ID"],
            "published_date": record.get("cveMetadata", {}).get("datePublished", ""),
            "updated_date": record.get("cveMetadata", {}).get("dateUpdated", ""),
            "description": get_description(record),
            "cvss_list": get_cvss(record),
            "cpe_list": get_cpe(record),
            "cwe": get_cwe(record, cwe_dict),
        })
        print(row["ID"], flush=True)

    save_json("result_task_2.json", result)
    print("task 2:", len(result))


def task_3():
    root = ET.Element("vulnerabilities")

    for row in read_json("result_task_2.json"):
        item = ET.SubElement(root, "vulnerability")

        for key in [
            "ID",
            "vendor_release_date",
            "vendor_release_url",
            "url",
            "published_date",
            "updated_date",
            "description",
        ]:
            child = ET.SubElement(item, key)
            child.text = str(row.get(key, ""))

        cvss_list = ET.SubElement(item, "cvss_list")
        for cvss in row["cvss_list"]:
            child = ET.SubElement(cvss_list, "cvss", {
                "version": str(cvss["version"]),
                "score": str(cvss["score"]),
                "severity": str(cvss["severity"]),
            })
            child.text = cvss["vector"]

        cpe_list = ET.SubElement(item, "cpe_list")
        for cpe in row["cpe_list"]:
            child = ET.SubElement(cpe_list, "cpe")
            child.text = cpe

        cwe_list = ET.SubElement(item, "cwe_list")
        for cwe_id, cwe in row["cwe"].items():
            child = ET.SubElement(cwe_list, "cwe", {
                "id": cwe_id,
                "name": cwe["name"],
            })
            child.text = cwe["description"]

    xml = ET.tostring(root, encoding="utf-8")
    pretty_xml = minidom.parseString(xml).toprettyxml(indent="  ", encoding="utf-8")
    Path("result_task_3.xml").write_bytes(pretty_xml)
    print("task 3")


def task_4():
    schema = read_json("json_schema.json")
    data = read_json("result_task_2.json")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))

    if not errors:
        print("validation ok")
        return

    for error in errors:
        path = "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in error.path)
        print(path, error.message)


def main():
    if len(sys.argv) < 2:
        print("usage: python main.py task1|task2|task3|task4|all")
        return

    if sys.argv[1] == "task1":
        task_1()
    elif sys.argv[1] == "task2":
        task_2()
    elif sys.argv[1] == "task3":
        task_3()
    elif sys.argv[1] == "task4":
        task_4()
    elif sys.argv[1] == "all":
        task_1()
        task_2()
        task_3()
        task_4()


if __name__ == "__main__":
    main()
