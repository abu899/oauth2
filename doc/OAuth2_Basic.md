# OAuth 2.0

## Fundamentals

### Introduction

OAuth = Open + Authorization (RFC 6749)

- 어플리케이션이 사용자를 대신해서 사용자의 자원에 대한 제한된 액세스를 얻기 위한 승인 상호작용을 하는 것
- 사용자의 자원(보호된 자원)에 대한 접근에 대한 권한을 획득 하는 것
- Delegated authorization framework
  - 위임 인가 프레임 워크
  - 어플리케이션이 사용자의 데이터에 접근하도록 권한을 부여한다 

OAuth 2.0 이전 방식의 문제점

1. 아이디와 패스워드가 노출되어 보안에 취약하다
   - 물론 SSL을 통해 암호화가 가능하다
2. 모든 서비스에 대한 제한없는 접근이 가능
3. 클라이언트 어플리케이션을 신뢰할 수 없음

OAuth 2.0의 장점

1. 아이디와 패스워드로 로그인 할 필요가 없다
2. 서비스의 범위를 제한할 수 있다
3. 클라이언트 어플리케이션에 대한 신뢰여부를 판단할 필요가 없다

### Roles

- Resource Owner
  - 보호된 자원에 대한 접근 권한을 부여할 수 있는 주체
  - 즉, 자원의 주인이자 `사용자`
  - 사용자를 대신해서 작동하는 모든 클라이언트는, 우선적으로 `사용자의 허가`를 받아야한다
- Resource Server
  - 클라이언트에서 접근하는 사용자의 `자원이 포함된 서버`
  - 즉, 자원을 가진 서버
  - 액세스 토큰을 수락 및 검증할 수 있어야 한다
  - 권한 체계에 따라 요청을 승인할 수 있어야 한다
- Authorization Server
  - 클라이언트의 권한 부여 요청을 승인하거나 거부하는 서버
  - 사용자가 클라이언트에게 권한 부여 요청 승인은, 사용자가 `인가서버`에 클라이언트에게 권한 부여를 해야된다고 알려야한다
  - 사용자가 클라이언트에게 권한 부여 요청을 승인한 후, `access token`을 클라이언트에게 발급하는 역할
- Client
  - 사용자를 대신하여 권한을 부여받아 사용자의 리소스에 접근하는 `어플리케이션`
  - 사용자를 권한 부여 서버로 안내하거나, 상호작용 없이 권한 부여 서버로부터 직접 권한을 얻을 수 있따.

## Client Types

<p align="center"><img src="img/client_type.png" width="80%"></p>

Client 는 사용자를 대신해서 사용자가 속한 `Resource server`에게 사용자의 자원을 가지고와서 사용하기 위한 어플리케이션.
인증 서버에서 클라이언트를 등록할 때, 자격 증명인 `client id`와 `secret` 을 받게된다.

### 기밀 클라이언트(Confidential)

기밀 클라이언트는 `client secret`의 기밀성을 유지할 수 있는 클라이언트

- 일반적으로 사용자가 소스코드에 액세스할 수 없는 서버에서 실행되는 응용프로그램
- 서버측 언어로 작성된다(Java, PHP, Node.js)
- 이런 유형의 어플리케이션은 웹 서버에서 실행되기 때문에 일반적으로 `웹 앱`이라고 한다

### 공개 클라이언트(Public)

공개 클라이언트는 `client secret`의 기밀을 유지할 수 없고, secret 이 사용되지 않는다

- 브라우저(SPA)에서 실행되는 JavaScript 어플리케이션, Android, IOS 등
- 디스어셈블러나 디버깅 도구를 통해 바이너리, 실행 코드를 통해 기밀 정보를 추출할 수 있기에 공개로 간주한다
- 서버측이 아닌 리소스 소유자가 사용하는 장치에서 실행되는 모든 클라이언트는 공개 클라이언트

## Token Types

### Access Token

클라이언트에서 사용자의 보호된 리소스에 접근하기 위해 사용하는 일종의 자격 증명

- `Resource Owner`가 클라이언트에게 부여한 권한의 표현
- 일반적으로 JWT 형식을 취하지만 사양에 따라 그럴 필요는 없음
- 토큰에는 액세스 기간, 범위, 서버에 필요한 기타 정보가 존재
- 식별자(Identifier) 타입과 자체포함(Self-contained) 타입이 있다
  - 식별자 타입
    - 토큰 안에 유의미한 정보가 포함되어 있지않다, 단순한 식별자의 역할
    - 인증서버에 토큰의 내용을 저장하고 있기 때문에, 리소스 서버에서 인증 서버로 토큰 유효성과 정보를 검사한다
    - 따라서, 인증서버에 대한 채널을 오픈해야되고 네트워크 비용이 증가한다
  - 자체포함 타입
    - 토큰 안에 유의미한 정보가 포함되어 있다, JWT.
    - 리소스 서버는 인증서버와 통신할 필요없이 자체 포함된 토큰의 유효성을 검증할 수 있다.
    - 특정 암호화 알고리즘에 의해 개인키로 서명되고 공개키로 검증할 수 있다.

### Refresh Token

액세스 토큰이 만료된 후 액세스 토큰을 얻기 위해 클라이언트에서 사용하는 자격 증명

- 만료된 경우, 클라이언트는 인증서버로 `refresh token` 을 전달
- 인증서버는 `refresh token `의 유효성을 검증하고 새로운 액세스 토큰을 전달한다

### ID Token

향후 추가

### Authorization Code

- 실습 중에 response type 을 code 로 해서 전달했을 때 받는 값
- 권한 부여 흐름에서 사용되며, 클라이언트가 `액세스 토큰과 교환하는 임시 코드`이다.

## Grant Type

### 매개변수 용어

- client id
  - 인가서버에 등록된 클라이언트의 고유한 키
- client secret
  - 인가서버에 등록된 클라이언트의 client id 에 대한 비밀 키
- response type
  - 어플리케이션이 권한 부여 코드 흐름을 진행하고 있음을 인증 서버에 알림
  - code, token, id_token 의 타입이 있으며, token, id_token 은 implicit 권한 부여 유형에서 지원
  - 서버가 쿼리 문자열에 인증코드, 코드등을 반환한다
- grant_type
  - 권한 부여 타입 지정
  - authorization code, password, client credentials, refresh token
- redirect_uri
  - 사용자가 클라이언트를 성공적으로 승인하게 되면, 권한 부여 서버가 사용자를 다시 클라이언트로 리디렉션
  - 초기 권한 요청에 포함되는 경우에도 이를 포함해야하며, 이 경우에는 토큰 발행 때에도 동일하게 요청해야하며 이 둘은 일치해야한다.
- scope
  - 클라이언트가 사용자 데이터에 접근하는 것을 제한하기 위해 사용
  - 특정 스코프로 제한된 인가 권한을 발행함으로서, 데이터 접근을 제한한다.
- state
  - 클라이언트는 임의의 문자열을 생성하여 요청하고, 사용자에 의해 승인된 후 동일한 값이 반환되는지 확인
  - CSRF 공격을 방지하는데 사용한다

### Authorization Code Grant

웹 어플리케이션에서 가장 많이 사용되며, 보안적으로도 가장 안전하다.

#### 흐름 및 특징

- 사용자가 어플리케이션을 승인하면 인가서버는 `Redirect URI`로 임시 코드(Authorization Code)를 담아서 어플리케이션으로 전달
- 클라이언트는 임시코드를 가지고 인가서버에 전달하여 액세스 토큰을 획득 -> `권한 부여 획득`
  - 어플리케이션 또한 `cliend_id`와 `client_secret`를 임시코드와 함께 전달하므로, 임시코드 후킹의 위험이 줄어든다
- 액세스 토큰이 사용자나 브라우저에 표시되지 않고 어플리케이션에 다시 전달하는 가장 안전한 방법이다
- 기밀 클라이언트 방식

#### 권한부여 코드(임시코드) 요청 시 매개 변수

- response_type=code (필수)
- client_id (필수)
- redirect_uri (선택)
- scope (선택)
- state (선택)

#### 액세스 토큰 교환 요청 시 매개 변수

- grant_type=authorization_code (필수)
- 권한부여 코드 (필수)
- redirect_uri (권한부여 코드 요청시 리다이렉션 URI를 전달했다면 필수)
- client_id (필수)
- client_secret (필수)

### Implicit Grant

#### 흐름 및 특징

- 클라이언트에서 javascript 및 HTML 소스코드를 다운로드한 후 브라우저는 서비스에 직접 API 요청을 진행한다.
- 즉, `임시코드 교환단계를 건너뛰고 바로 토큰을 요청`하여 액세스 토큰이 쿼리 문자열로 클라이언트에 즉시 반환된다
- back channel 이 없기 때문에, refresh token 을 사용하지 못한다
- Oauth 2.1 에서부터는 Deprecate 되었다
- 공개 클라이언트

#### 권한부여 승인 요청 시 매개 변수

- grant_type=token (필수)
- client_id (필수)
- redirect_uri (필수)
- scope (선택)
- state (선택)

### Resource Owner Password Credentials Grant

#### 흐름 및 특징

- 어플리케이션이 사용자 이름과 암호를 액세스 토큰으로 교환할 때 사용한다
- 그렇기 때문에 신뢰할만한 자사 어플리케이션에서만 사용해야 한다

#### 권한부여 승인 요청 시 매개 변수

- grant_type=password (필수)
- username (필수)
- password (필수)
- client_id (필수)
- client_secret (필수)
- scope (선택)

### Client Credentials Grant

#### 흐름 및 특징

- 어플리케이션이 리소스 소유자인 동시에 클라이언트 역할을 한다
  - 즉, 자기 자신이 어플리케이션을 사용할 목적으로 사용하는 것
- `Client id` 와 `Client Secret`을 통해 액세스 토큰을 바로 발급 받을 수 있기 때문에 Refresh token 을 발급하지 않는다
- Client 정보 기반이기에, 사용자 정보를 제공하지 않는다

#### 권한부여 승인 요청 시 매개 변수

- grant_type=client_credentials (필수)
- client_id (필수)
- client_secret (필수)
- scope (선택)

### Refresh Token Grant

#### 흐름 및 특징

- 액세스 토큰이 발급될 때 함께 제공되는 토큰
- 액세스 토큰이 만료되더라도 리프레시 토큰이 유효하다면 인증과정을 처음부터 반복하지 않아도 된다
- 리프레시 토큰은 폐기 혹은 재사용될 수 있다

#### 권한부여 승인 요청 시 매개 변수

- grant_type=refresh_token (필수)
- refresh_token (필수)
- client_id (필수)
- client_secret (필수)

## Open ID Connect

- Open ID Connect 는 OAuth 2.0 프로토콜 위에 구축된 ID 계층
  - OAuth 2.0 최상위 레이어에 위치 - 인증
  - OAuth 2.0은 사실 Authorization Framework - 인증도 가능하지만 사실 인가 프레임워크
  - 그렇기에 OAuth 2.0의 목적은 Access token 을 얻는 것 
  - 그래서 인증만을 위한 프로토콜을 만든게 Open ID Connect
- OAuth 2.0 을 확장하여 인증방식을 표준화한 OAuth 2.0 기반의 `인증 프로토콜`
- scope 지정 시 openid 를 포함하면 open id connect 사용이 가능
  - 인증에 대한 정보는 ID Token 이라는 JWT 로 반환
- Open ID Connect 는 클라이언트가 `사용자 ID 를 확인할 수 있게하는 보안 토큰(ID TOKEN)`

### ID Token

ID 토큰은 사용자가 인증되었음을 증명하는 결과물이다. 반면 Access Token 은 인증을 나타내지 않는다.
따라서, `OpenID Connect(OIDC)` 요청 시, access token 과 함께 ID 토큰이 전달된다.
어플리케이션은 공개 키로 ID 토큰을 검증 및 유효성을 검사하고 만료 여부 등의 `Claim`을 확인한다.
어플리케이션에서는 클레임 정보에 포함된 여러 정보들을 활용해 인증관리를 사용할 수 있다.

- ID Token vs Access Token
  - ID 토큰은 API 요청에 사용되지 않으며, 신원확인을 위한 용도로만 사용되어야 한다
    - 즉, 로그인 용도
  - Access Token 은 인증을 위해 사용되지 않으며, 리소스에 접근하기 위한 용도로 사용되어야 한다
    - 즉 자원을 가져오는 용도

### 용어

- OIDC 상호 작용 행위자
  - OpenID Provider(OP)
    - Open ID 제공자로, 최종 사용자를 인증하고 인증 결과와 사용자 정보를 제공하는 OAuth 2.0 서버
  - Relying Party(RP)
    - 신뢰 당사자, 인증 요청을 처리하기위해 OP 에 의존하는 어플리케이션

### 흐름

1. RP는 OP에 권한 부여 요청을 보냄
2. OP는 최종 사용자(Resource Owner)를 인증하고 권한을 획득
3. OP는 ID 토큰과 액세스 토큰을 반환
4. RP는 액세스 토큰을 사용해 UserInfo 엔드포인트에 요청을 보낼 수 있음
5. UserInfo 엔드포인트는 최종 사용자에 대한 클레임을 반환