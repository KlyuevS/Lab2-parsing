import json
import re
import sys
from datetime import datetime

import requests
from bs4 import BeautifulSoup


SOURCE_URL = "https://tomcat.apache.org/security-9.html"


def save_json(file_name, data):
    with open(file_name, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


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


def main():
    if len(sys.argv) < 2:
        print("usage: python main.py task1")
        return

    if sys.argv[1] == "task1":
        task_1()


if __name__ == "__main__":
    main()
