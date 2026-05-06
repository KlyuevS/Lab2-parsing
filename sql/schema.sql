create table if not exists vulnerability (
    id bigserial primary key,
    name text not null unique,
    vendor_release_date date not null,
    vendor_release_url text not null,
    url text not null,
    published_date timestamptz not null,
    updated_date timestamptz not null,
    description text not null
);

create table if not exists cvss_score (
    id bigserial primary key,
    vulnerability_id bigint not null references vulnerability(id),
    version text not null,
    score numeric(3, 1),
    vector text not null,
    severity text not null,
    unique (vulnerability_id, version, vector)
);

create table if not exists cpe (
    id bigserial primary key,
    name text not null unique
);

create table if not exists vulnerability_cpe (
    vulnerability_id bigint not null references vulnerability(id),
    cpe_id bigint not null references cpe(id),
    primary key (vulnerability_id, cpe_id)
);

create table if not exists cwe (
    id bigserial primary key,
    name text not null,
    title text not null,
    description text not null,
    unique (name)
);

create table if not exists vulnerability_cwe (
    vulnerability_id bigint not null references vulnerability(id),
    cwe_id bigint not null references cwe(id),
    primary key (vulnerability_id, cwe_id)
);
