CREATE TABLE csrf (
    csrf text,
    ip text
);

CREATE TABLE reports (
    id serial primary key,
    editor text,
    name text,
    sql text,
    template text,
    template_headers text,
    defaults text DEFAULT '{}',
    last_modified timestamp with time zone DEFAULT now() NOT NULL
);
