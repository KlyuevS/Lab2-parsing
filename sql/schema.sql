create table if not exists vulnerability (
    id text primary key,
    vendor_release_date date not null,
    vendor_release_url text not null,
    url text not null,
    published_date timestamptz not null,
    updated_date timestamptz not null,
    description text not null
);

create table if not exists cvss_score (
    id bigserial primary key,
    cve_id text not null references vulnerability(id),
    version text not null,
    score numeric(3, 1),
    vector text not null,
    severity text not null
);

create table if not exists cpe (
    id bigserial primary key,
    name text not null unique
);

create table if not exists vulnerability_cpe (
    cve_id text not null references vulnerability(id),
    cpe_id bigint not null references cpe(id),
    primary key (cve_id, cpe_id)
);

create table if not exists cwe (
    id text primary key,
    name text not null,
    description text not null
);

create table if not exists vulnerability_cwe (
    cve_id text not null references vulnerability(id),
    cwe_id text not null references cwe(id),
    primary key (cve_id, cwe_id)
);
