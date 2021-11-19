---
# try also 'default' to start simple
theme: default

# apply any windi css classes to the current slide
class: 'text-center'
# https://sli.dev/custom/highlighters.html
highlighter: shiki
# show line numbers in code blocks
lineNumbers: false
# some information about the slides, markdown enabled
info: |
    ## Slidev Starter Template
    Presentation slides for developers.

    Learn more at [Sli.dev](https://sli.dev)
# persist drawings in exports and build
drawings:
    persist: false
---

## Spring Security の password の Encode について

<br> 
<br>

---

## 目次

<br> 
<br>

-   パスワードのハッシュ化の流れ
-   BcryptPasswordEncoder はランダムの salt をハッシュ化に使用している
-   ログイン時にパスワードを検証する流れ
-   まとめ、感想

---

## パスワードのハッシュ化の流れ

<br> 
<br>

-   row password(素のパスワード) と salt をもとにハッシュ化されている
    -   salt とは元のデータに付加するランダムな文字列
    -   ソルト処理(salt を付加すること)によりハッシュ値から元のデータを推測されるリスクを軽減できる

<br>

```java{all|1-2|4,7|4,12}
// パスワードをハッシュ化する処理
bcrypt.encode("hogefuga-password")

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

---

## パスワードのハッシュ化の流れ

<br> 
<br>

-   rounds と salt として使われる値に分けられる
    -   [rounds はハッシュ化の計算をする回数](https://github.com/spring-projects/spring-security/blob/main/crypto/src/main/java/org/springframework/security/crypto/bcrypt/BCrypt.java#L524)

```java
// org/springframework/security/crypto/bcrypt/BCrypt.java

// 使用される salt の例 `$2a$10$P7ljPh0q/zvDAefOjBQrGe`
return hashpw(passwordb, salt);
```

```java{all|7,8}
		if (salt.charAt(0) != '$' || salt.charAt(1) != '2') {
			throw new IllegalArgumentException("Invalid salt version");
		}

		(略)

		rounds = Integer.parseInt(salt.substring(off, off + 2));
        real_salt = salt.substring(off + 3, off + 25);
```

---

## パスワードのハッシュ化の流れ

<br> 
<br>

-   パスワードがハッシュ化される
    -   ex.) `$2a$10$P7ljPh0q/zvDAefOjBQrGe6EimXsAnYLb5vPL7pYQI0wv6nOY2OeO`
        -   `$2a` が BCrypt algorithm version
        -   `$10` が round(アルゴリズムの強度)
        -   `$P7ljPh0q/zvDAefOjBQrGe` が **ランダム生成された salt(後述)**
        -   `6EimXsAnYLb5vPL7pYQI0wv6nOY2OeO` が **平文で受け取ったパスワードをハッシュ化したもの**

<br>

```java
// org/springframework/security/crypto/bcrypt/BCrypt.java

		hashed = B.crypt_raw(passwordb, saltb, rounds, minor == 'x', minor == 'a' ? 0x10000 : 0);
```

---

## 目次

<br> 
<br>

~~-   パスワードのハッシュ化の流れ~~
-   BcryptPasswordEncoder はランダムの salt をハッシュ化に使用している
-   ログイン時にパスワードを検証する流れ
-   まとめ、感想

---

### BcryptPasswordEncoder はランダムの salt をハッシュ化に使用している

<br> 
<br>

-   salt の生成箇所

```java{all|1,8}
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

```java{all|1,3}
private String getSalt() {
		if (this.random != null) {
			return BCrypt.gensalt(this.version.getVersion(), this.strength, this.random);
		}
		return BCrypt.gensalt(this.version.getVersion(), this.strength);
	}
```

---

### BcryptPasswordEncoder はランダムの salt をハッシュ化に使用している

<br> 
<br>

-   [同じパスワードを 2 回ハッシュ化した結果が **異なる値になる**](https://github.com/KiyotaTakeshi/spring-security-encoder-playground/blob/main/src/test/kotlin/com/kiyotakeshi/springsecurityencoderplayground/PasswordEncodingTest.kt#L14-L33)

```kotlin{all|3-6|6}
    @Test
    fun `"generated different hash using different salt"`() {
        val bcrypt: PasswordEncoder = BCryptPasswordEncoder()
        val bcryptEncodedPass1 = bcrypt.encode(password)
        val bcryptEncodedPass2 = bcrypt.encode(password)
        assertNotEquals(bcryptEncodedPass1, bcryptEncodedPass2)
    }
```

---

### BcryptPasswordEncoder はランダムの salt をハッシュ化に使用している

<br> 
<br>

-   [同じ salt を使えば同じエンコード結果(ハッシュ値)になる](https://github.com/KiyotaTakeshi/spring-security-encoder-playground/blob/main/src/test/kotlin/com/kiyotakeshi/springsecurityencoderplayground/PasswordEncodingTest.kt#L35-L44)

<br>
<br>

```kotlin{all|3-7|6}
    @Test
    fun `"generated same hash using same salt"`() {
        val customEncoder: PasswordEncoder = CustomEncoder()
        val customEncodedPass1 = customEncoder.encode(password)
        val customEncodedPass2 = customEncoder.encode(password)
        assertEquals(customEncodedPass1, customEncodedPass2)
    }
```

---

## ログイン時にパスワードを検証する流れ

<br>
<br>

-   DB や memory からユーザ情報を取得

```java{all|1,4}
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

---

## ログイン時にパスワードを検証する流れ

<br>
<br>

-   リクエストから受け取ったパスワードと取得したユーザのパスワードを比較

```java{all|1,3}
// org/springframework/security/authentication/dao/DaoAuthenticationProvider.java

if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
			this.logger.debug("Failed to authenticate since password does not match stored value");
			throw new BadCredentialsException(this.messages
					.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
```

---

## ログイン時にパスワードを検証する流れ

<br>
<br>

-   リクエストから受け取ったパスワードと取得したユーザのパスワードを比較

```java
// this.passwordEncoder: BCryptPasswordEncoder@13893
// presentedPassword: 1qazxsw2
// userDetails.getPassword(): $2a$10$BYNYHWPZQzWyPAZRwLuzSO1UPTE2jTdziYjoHw8gRjn95t7zf2fs6
if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
```

<br>

-   つまり...
    -   **リクエストをハッシュ化した値と保存されているハッシュ化された値を比較している**

```java
BCryptPasswordEncoder.matches("1qazxsw2", "$2a$10$BYNYHWPZQzWyPAZRwLuzSO1UPTE2jTdziYjoHw8gRjn95t7zf2fs6")
```

---

## ログイン時にパスワードを検証する流れ

<br>
<br>

-   リクエストをハッシュ化した値と保存されているハッシュ化された値を比較している

```java{all|3}
// org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.java

		return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
```

-   **保存されているハッシュから round と salt を取り出して** リクエストの値をハッシュ化して比較

```java{all|7-11}
// org/springframework/security/crypto/bcrypt/BCrypt.java

		return hashpw(passwordb, salt);

		(略)

    	// ex.) `$2a$10$P7ljPh0q/zvDAefOjBQrGe6EimXsAnYLb5vPL7pYQI0wv6nOY2OeO`
        //      `$10` が round
        //      `$P7ljPh0q/zvDAefOjBQrGe` が salt
		rounds = Integer.parseInt(salt.substring(off, off + 2));
        real_salt = salt.substring(off + 3, off + 25);
```

---

# まとめ、感想

<br> 
<br>

DB から取得したハッシュ化されたユーザのパスワードの salt と round をつかって、    
リクエストをハッシュ化し、それらが一致するかをチェックしている。

また、BcryptPasswordEncoder はランダムで salt を生成し、ハッシュ化する。

---

# まとめ、感想

<br>
<br>

- パスワードのハッシュ化を自前で実装するのは大変そう
	- フレームワーク(Spring Security)の恩恵をうけよう 🙏🏿

- 体力があるときには、ソースコードを呼んで内部の仕組みを散策すると発見がある
