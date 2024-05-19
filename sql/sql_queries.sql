drop table if exists donororg_user1, donorper_user2;

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

create table user(
    userid int primary key,
    username varchar(255)
);
