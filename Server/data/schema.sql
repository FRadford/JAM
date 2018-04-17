drop table if exists users;
create table users (
    id integer primary key,
    username text not null unique,
    password blob not null,
    salt text not null
);