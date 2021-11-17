# spring-security-encoder-playground

```shell
# コンテナを起動
# テスト用のユーザデータも流し込まれる
$ docker compose up -d

$ docker compose ps
NAME                     COMMAND                  SERVICE             STATUS              PORTS
password-encoder-mysql   "docker-entrypoint.s…"   mysql               running             0.0.0.0:3306->3306/tcp
```

TODO: 動作確認方法を追記

## row password と salt をもとにハッシュ化されている

```java
// org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.java

	@Override
	public String encode(CharSequence rawPassword) {
		if (rawPassword == null) {
			throw new IllegalArgumentException("rawPassword cannot be null");
		}
		String salt = getSalt();
		return BCrypt.hashpw(rawPassword.toString(), salt);
	}
```

- 生成される salt の例 `$2a$10$P7ljPh0q/zvDAefOjBQrGe`

```java
// org/springframework/security/crypto/bcrypt/BCrypt.java

return hashpw(passwordb, salt);
```

```java
// org/springframework/security/crypto/bcrypt/BCrypt.java

		if (salt.charAt(0) != '$' || salt.charAt(1) != '2') {
			throw new IllegalArgumentException("Invalid salt version");
		}
```

- rounds と salt として使われる値に分けられる

```java
		rounds = Integer.parseInt(salt.substring(off, off + 2));
        real_salt = salt.substring(off + 3, off + 25);
```

- パスワードがハッシュ化される `$2a$10$P7ljPh0q/zvDAefOjBQrGe6EimXsAnYLb5vPL7pYQI0wv6nOY2OeO`

```java
		hashed = B.crypt_raw(passwordb, saltb, rounds, minor == 'x', minor == 'a' ? 0x10000 : 0);
```

## BcryptPasswordEncoder はランダムの salt をもとにハッシュ化している

```java
// org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.java

	@Override
	public String encode(CharSequence rawPassword) {
		if (rawPassword == null) {
			throw new IllegalArgumentException("rawPassword cannot be null");
		}
		String salt = getSalt();
		return BCrypt.hashpw(rawPassword.toString(), salt);
	}
```

- salt の生成箇所

```java
// org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.java

private String getSalt() {
		if (this.random != null) {
			return BCrypt.gensalt(this.version.getVersion(), this.strength, this.random);
		}
		return BCrypt.gensalt(this.version.getVersion(), this.strength);
	}
```

```java
// org/springframework/security/crypto/bcrypt/BCrypt.java

		return gensalt(prefix, log_rounds, new SecureRandom());
```

- 同じ salt を使えば同じエンコード結果(ハッシュ値)になることは [テストコードにて確認済み](./src/test/kotlin/com/kiyotakeshi/springsecurityencoderplayground/PasswordEncodingTest.kt)

TODO: もうちょいちゃんと書く
### ログイン時にパスワードを検証する流れ

```java
// org/springframework/security/authentication/dao/DaoAuthenticationProvider.java
		try {
                UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
                if (loadedUser == null) {
                throw new InternalAuthenticationServiceException(
                "UserDetailsService returned null, which is an interface contract violation");
                }
                return loadedUser;
                }
```

```java
if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
			this.logger.debug("Failed to authenticate since password does not match stored value");
			throw new BadCredentialsException(this.messages
					.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
```

```java
// presentedPassword: 1qazxsw2
// userDetails.getPassword(): $2a$10$BYNYHWPZQzWyPAZRwLuzSO1UPTE2jTdziYjoHw8gRjn95t7zf2fs6
// this.passwordEncoder: BCryptPasswordEncoder@13893
if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {

// つまりは！
// BCryptPasswordEncoder.matches("1qazxsw2", "$2a$10$BYNYHWPZQzWyPAZRwLuzSO1UPTE2jTdziYjoHw8gRjn95t7zf2fs6")
```

```java
// org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.java
		return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
```

```java
// org/springframework/security/crypto/bcrypt/BCrypt.java
		return hashpw(passwordb, salt);
```

```java
// org/springframework/security/crypto/bcrypt/BCrypt.java

		rounds = Integer.parseInt(salt.substring(off, off + 2));

        real_salt = salt.substring(off + 3, off + 25);
```