create schema imanidonationdb;

use imanidonationdb;

create table donororg_user(
org_userid int auto_increment primary key,
username varchar(255),
email varchar(255),
password varbinary(255)
);

create table donorper_user(
per_userid int auto_increment primary key,
username varchar(255),
email varchar(255),
password varbinary(255)
);