-- plain text password is `1qaazxsw2`
-- @see com/kiyotakeshi/springsecurityencoderplayground/PasswordEncodingTest.kt
insert into user
values (1, 'admin@example.com', '$2a$10$hBUz.jpzVOMgLq2gPmQAvOmRewcppw/efvrExgZcfma8VmXHckTK6', 'kendrick'),
       (2, 'user@example.com', '$2a$10$BYNYHWPZQzWyPAZRwLuzSO1UPTE2jTdziYjoHw8gRjn95t7zf2fs6', 'tyler');
