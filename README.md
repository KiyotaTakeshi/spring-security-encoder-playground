# spring-security-encoder-playground

```shell
# コンテナを起動
# テスト用のユーザデータも流し込まれる
$ docker compose up -d

$ docker compose ps
NAME                     COMMAND                  SERVICE             STATUS              PORTS
password-encoder-mysql   "docker-entrypoint.s…"   mysql               running             0.0.0.0:3306->3306/tcp
```

---
## [プレゼンテーション資料](./presentation-material/README.md)

- [Slidev](https://github.com/slidevjs/slidev) を使用

---
## 動作確認方法

```shell
$ export JAVA_HOME=`/usr/libexec/java_home -v 11`

$ java -version                                  
openjdk version "11.0.11" 2021-04-20 LTS
OpenJDK Runtime Environment Corretto-11.0.11.9.1 (build 11.0.11+9-LTS)
OpenJDK 64-Bit Server VM Corretto-11.0.11.9.1 (build 11.0.11+9-LTS, mixed mode)

# @see https://docs.spring.io/spring-boot/docs/current/gradle-plugin/reference/htmlsingle/#running-your-application
$ ./gradlew bootRun

# or make executable jar
# $ ./gradlew clean build
# $ java -jar build/libs/spring-security-encoder-playground-0.0.1-SNAPSHOT.jar
```

---
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

### ログイン時にパスワードを検証する流れ

- DB や memory からユーザ情報を取得

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

- リクエストから受け取ったパスワードと取得したユーザのパスワードを比較

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
```

- **リクエストをハッシュ化した値と保存されているハッシュ化された値を比較している**

```
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

- **保存されているハッシュから round と salt を取り出して** リクエストの値をハッシュ化して比較

```java
// org/springframework/security/crypto/bcrypt/BCrypt.java

		rounds = Integer.parseInt(salt.substring(off, off + 2));

        real_salt = salt.substring(off + 3, off + 25);
```
