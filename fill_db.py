import json
import os

import psycopg


DB_URL = os.getenv("DB_URL", "postgresql://lab2:lab2@localhost:5432/lab2")


def main():
    with open("result_task_2.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    with psycopg.connect(DB_URL) as conn:
        with conn.cursor() as cur:
            for row in data:
                cur.execute(
                    """
                    insert into vulnerability
                    (name, vendor_release_date, vendor_release_url, url, published_date, updated_date, description)
                    values (%s, %s, %s, %s, %s, %s, %s)
                    on conflict (name) do update set
                        vendor_release_date = excluded.vendor_release_date,
                        vendor_release_url = excluded.vendor_release_url,
                        url = excluded.url,
                        published_date = excluded.published_date,
                        updated_date = excluded.updated_date,
                        description = excluded.description
                    returning id
                    """,
                    (
                        row["ID"],
                        row["vendor_release_date"],
                        row["vendor_release_url"],
                        row["url"],
                        row["published_date"],
                        row["updated_date"],
                        row["description"],
                    ),
                )
                vulnerability_id = cur.fetchone()[0]

                for cvss in row["cvss_list"]:
                    cur.execute(
                        """
                        insert into cvss_score (vulnerability_id, version, score, vector, severity)
                        values (%s, %s, %s, %s, %s)
                        on conflict (vulnerability_id, version, vector) do update set
                            score = excluded.score,
                            severity = excluded.severity
                        """,
                        (vulnerability_id, cvss["version"], cvss["score"], cvss["vector"], cvss["severity"]),
                    )

                for cpe in row["cpe_list"]:
                    cur.execute(
                        "insert into cpe (name) values (%s) on conflict (name) do update set name = excluded.name returning id",
                        (cpe,),
                    )
                    cpe_id = cur.fetchone()[0]
                    cur.execute(
                        "insert into vulnerability_cpe (vulnerability_id, cpe_id) values (%s, %s) on conflict do nothing",
                        (vulnerability_id, cpe_id),
                    )

                for cwe_id, cwe in row["cwe"].items():
                    cur.execute(
                        """
                        insert into cwe (name, title, description)
                        values (%s, %s, %s)
                        on conflict (name) do update set
                            title = excluded.title,
                            description = excluded.description
                        returning id
                        """,
                        (cwe_id, cwe["name"], cwe["description"]),
                    )
                    cwe_pk = cur.fetchone()[0]
                    cur.execute(
                        "insert into vulnerability_cwe (vulnerability_id, cwe_id) values (%s, %s) on conflict do nothing",
                        (vulnerability_id, cwe_pk),
                    )

        conn.commit()
    print("db filled")


if __name__ == "__main__":
    main()
