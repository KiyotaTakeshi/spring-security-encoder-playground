create table user
(
    id        bigint              not null,
    email     varchar(256) unique not null,
    password  varchar(128)        not null,
    name      varchar(32)         not null,
    primary key (id)
)
    engine = InnoDB;