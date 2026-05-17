import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from xml.dom import minidom
from xml.etree import ElementTree as ET

import requests
from bs4 import BeautifulSoup
from jsonschema import Draft202012Validator


SOURCE_URL = "https://tomcat.apache.org/security-9.html"
CVE_API = "https://cveawg.mitre.org/api/cve/"
CVE_URL = "https://www.cve.org/CVERecord?id="
CWE_API = "https://cwe-api.mitre.org/api/v1/cwe/weakness/"


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


def get_json(url):
    for i in range(6):
        try:
            result = subprocess.run(
                ["curl", "-L", "--fail", "--silent", "--connect-timeout", "10", "--max-time", "30", url],
                capture_output=True,
                text=True,
                check=True,
            )
            return json.loads(result.stdout)
        except Exception:
            pass

        try:
            request = Request(url, headers={"User-Agent": "lab2-parser"})
            with urlopen(request, timeout=15) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception:
            if i == 5:
                raise
            time.sleep(1)


def read_cache(path):
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def write_cache(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)


def get_description(record):
    descriptions = record.get("containers", {}).get("cna", {}).get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return re.sub(r"\s+", " ", item.get("value", "")).strip()
    return ""


def get_cvss(record):
    result = []
    used = set()
    metrics = record.get("containers", {}).get("cna", {}).get("metrics", [])
    for adp in record.get("containers", {}).get("adp", []):
        metrics += adp.get("metrics", [])

    for metric in metrics:
        for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
            if key not in metric:
                continue
            item = metric[key]
            pair = (key, item.get("vectorString", ""))
            if pair in used:
                continue
            used.add(pair)
            result.append({
                "version": "cvss" + item.get("version", "").replace(".", ""),
                "score": item.get("baseScore"),
                "vector": item.get("vectorString", ""),
                "severity": item.get("baseSeverity", ""),
            })
    return result


def cpe_part(value):
    value = value.lower().strip()
    value = value.replace("apache software foundation", "apache")
    value = value.replace("apache tomcat", "tomcat")
    return re.sub(r"[^a-z0-9._-]+", "_", value).strip("_")


def parse_product_version(value):
    value = value.strip()
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:[-.]M(\d+)|[.]RC(\d+))?$", value)
    if not match:
        return None
    major, minor, patch, milestone, rc = match.groups()
    update = "*"
    if milestone:
        update = "milestone" + milestone
    if rc:
        update = "rc" + rc
    return int(major), int(minor), int(patch), update


def make_cpe(vendor, product, version_value):
    parsed = parse_product_version(version_value)
    if not parsed:
        return ""
    major, minor, patch, update = parsed
    version = f"{major}.{minor}.{patch}"
    return f"cpe:2.3:a:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*"


def expand_versions(start_value, end_value="", include_end=True):
    start = parse_product_version(start_value)
    if not start:
        return [start_value]
    if not end_value:
        return [start_value]

    end = parse_product_version(end_value)
    if not end:
        return [start_value, end_value]

    start_major, start_minor, start_patch, start_update = start
    end_major, end_minor, end_patch, end_update = end

    if start_major != end_major or start_minor != end_minor:
        return [start_value, end_value] if include_end else [start_value]

    result = []

    if start_update != "*":
        result.append(start_value)
        start_patch += 1

    last_patch = end_patch if include_end else end_patch - 1
    if end_update != "*":
        last_patch = end_patch - 1

    if last_patch >= start_patch and last_patch - start_patch <= 300:
        for patch in range(start_patch, last_patch + 1):
            result.append(f"{start_major}.{start_minor}.{patch}")

    if include_end and end_update != "*":
        result.append(end_value)

    return result or [start_value]


def version_tokens(value):
    return re.findall(r"\d+\.\d+\.\d+(?:[-.]M\d+|[.]RC\d+)?", value)


def infer_start_version(raw_version, end_value):
    end = parse_product_version(end_value)
    if not end:
        return ""
    major, minor, _patch, end_update = end
    if end_update.startswith("milestone"):
        return f"{major}.{minor}.0-M1"
    if re.search(rf"\b{major}\.{minor}\b", raw_version):
        return f"{major}.{minor}.0"
    return ""


def get_versions_from_record(version):
    raw_version = version.get("version", "")
    tokens = version_tokens(raw_version)

    if " to " in raw_version and len(tokens) >= 2:
        start, end = tokens[-2], tokens[-1]
        return expand_versions(start, end)

    if version.get("lessThanOrEqual"):
        start = tokens[-1] if tokens else infer_start_version(raw_version, version["lessThanOrEqual"])
        return expand_versions(start, version["lessThanOrEqual"]) if start else []

    if version.get("lessThan"):
        start = tokens[-1] if tokens else infer_start_version(raw_version, version["lessThan"])
        return expand_versions(start, version["lessThan"], include_end=False) if start else []

    return tokens or ([raw_version] if parse_product_version(raw_version) else [])


def previous_fixed_version(row):
    match = re.search(r"Fixed_in_Apache_Tomcat_(\d+)\.(\d+)\.(\d+)[.]M(\d+)", row.get("vendor_release_url", ""))
    if match:
        major, minor, patch, milestone = map(int, match.groups())
        if milestone > 1:
            return f"{major}.{minor}.{patch}-M{milestone - 1}"
        return ""

    match = re.search(r"Fixed_in_Apache_Tomcat_(\d+)\.(\d+)\.(\d+)", row.get("vendor_release_url", ""))
    if not match:
        return ""
    major, minor, patch = map(int, match.groups())
    if patch == 0:
        return ""
    return f"{major}.{minor}.{patch - 1}"


def get_cpe(record, row=None):
    result = []
    affected = record.get("containers", {}).get("cna", {}).get("affected", [])
    for item in affected:
        result += item.get("cpes", [])
        for version in item.get("versions", []):
            result += version.get("cpes", [])

        vendor = cpe_part(item.get("vendor", ""))
        product = cpe_part(item.get("product", ""))
        if vendor and product:
            for version in item.get("versions", []):
                if version.get("status") == "unaffected":
                    continue
                for value in get_versions_from_record(version):
                    cpe = make_cpe(vendor, product, value)
                    if cpe:
                        result.append(cpe)

    if not result and row:
        version = previous_fixed_version(row)
        if version:
            result.append(make_cpe("apache", "tomcat", version))

    return sorted(set(result))


def get_cwe_ids(record):
    result = set()
    containers = [record.get("containers", {}).get("cna", {})]
    containers += record.get("containers", {}).get("adp", [])

    problem_types = []
    for container in containers:
        problem_types += container.get("problemTypes", [])

    for problem_type in problem_types:
        for description in problem_type.get("descriptions", []):
            cwe_id = description.get("cweId")
            if cwe_id and cwe_id.startswith("CWE-"):
                result.add(cwe_id)
            for cwe_id in re.findall(r"CWE-\d+", description.get("description", "")):
                result.add(cwe_id)
    return sorted(result)


def get_cwe_info(cwe_ids):
    result = {}
    cwe_ids = sorted(cwe_ids)
    for i in range(0, len(cwe_ids), 50):
        part = cwe_ids[i:i + 50]
        numbers = [cwe_id.replace("CWE-", "") for cwe_id in part]
        data = get_json(CWE_API + ",".join(numbers))
        for weakness in data.get("Weaknesses", []):
            cwe_id = "CWE-" + weakness.get("ID", "")
            result[cwe_id] = {
                "name": weakness.get("Name", cwe_id),
                "description": weakness.get("Description", cwe_id),
            }
    for cwe_id in cwe_ids:
        result.setdefault(cwe_id, {"name": cwe_id, "description": cwe_id})
    return result


def load_cve(row):
    cache = Path(".cache/cve") / (row["ID"] + ".json")
    record = read_cache(cache)
    if record is None:
        record = get_json(CVE_API + row["ID"])
        write_cache(cache, record)
    print(row["ID"], flush=True)
    return row, record


def task_2():
    rows = read_json("result_task_1.json")
    loaded = []
    cwe_ids = set()

    with ThreadPoolExecutor(max_workers=12) as executor:
        for row, record in executor.map(load_cve, rows):
            loaded.append((row, record))
            cwe_ids.update(get_cwe_ids(record))

    cwe_dict = get_cwe_info(cwe_ids)
    result = []

    for row, record in loaded:
        result.append({
            **row,
            "url": CVE_URL + row["ID"],
            "published_date": record.get("cveMetadata", {}).get("datePublished", ""),
            "updated_date": record.get("cveMetadata", {}).get("dateUpdated", ""),
            "description": get_description(record),
            "cvss_list": get_cvss(record),
            "cpe_list": get_cpe(record, row),
            "cwe": {cwe_id: cwe_dict[cwe_id] for cwe_id in get_cwe_ids(record)},
        })

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

    print("validation failed")

    for field in ["cvss_list", "cpe_list", "cwe"]:
        ids = [row["ID"] for row in data if not row[field]]
        if ids:
            print(field + ":", ", ".join(ids))

    other_errors = []
    for error in errors:
        path = "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in error.path)
        if not any(path.endswith("." + field) for field in ["cvss_list", "cpe_list", "cwe"]):
            other_errors.append((path, error.message))

    for path, message in other_errors:
        print(path, message)


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
