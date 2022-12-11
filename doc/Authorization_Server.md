# Authorization Server

OAuth 2.1 및 OpenId Connect 1.0 사양 및 기타 관련 사양 구현을 제공하는 프레임워크.

## Fundamental

- 권한 부여
  - 인증 코드
  - 사용자 동의
  - 클라이언트 자격 증명
  - 토큰 및 리프레시 토큰 발급
- 토큰 형식
  - 독립형(JWT)
  - 참조 (Opaque)
- 클라이언트 인증
  - client secret basic
  - client secret post
  - client secret jwt
  - private key jwt
  - none (공개 클라이언트)
- 프로토콜 엔드포인트
  - OAuth2 인증 엔드포인트
  - OAuth2 토큰 엔드포인트
  - OAuth2 토큰 검사 엔드 포인트
  - OAuth2 토큰 해지 엔드 포인트
  - OAuth2 권한 부여 서버 메타데이터 엔드포인트
  - JWK 엔드포인트 설정
  - OIDC 1.0 공급자 구성 엔드포인트
  - OIDC 1.0 사용자 정보 엔드포인트
  - OIDC 1.0 클라이언트 등록 엔드포인트

### OAuth2AuthorizationServerConfigurer

- OAuth2ClientAuthenticationConfigurer
  - OAuth 2.0 `클라이언트 인증 엔드포인트` 설정 클래스
  - RequestMatcher
    - POST, `/oauth2/token`
    - POST, `/oauth2/intropspect`
    - POST, `/oauth2/revoke`
  - OAuth2ClientAuthenticationFilter
  - OAuth2ClientAuthenticationProvider
- OAuth2AuthorizationEndpointConfigurer
  - OAuth 2.0 `권한 부여 엔드포인트` 설정 클래스
  - RequestMatcher
    - GET, `/oauth2/authorize`
    - POST, `/oauth2/authorize`
  - OAuth2AuthorizationEndpointFilter
  - OAuth2AuthorizationCodeRequestAuthenticationProvider
- OAuth2TokenEndpointConfigurer
  - OAuth 2.0 `토큰 엔드포인트` 설정 클래스
  - RequestMatcher
    - POST, `/oauth2/token`
  - OAuth2TokenEndpointFilter
  - OAUth2`AuthorizationCode`AuthenticationProvider
  - OAUth2`RefreshToken`AuthenticationProvider
  - OAuth2`ClientCredential`AuthenticationProvider
- OAuth2TokenRevocationEndpointConfigurer
  - OAuth 2.0 `토큰 취소 엔드포인트` 설정 클래스
  - RequestMatcher
    - POST, `/oauth2/revoke`
  - OAuth2TokenRevocationEndpointFilter
  - OAuth2TokenRevocationAuthenticationProvider
- OidcConfigurer
  - OpenID Connect 엔드포인트 설정 클래스
  - RequestMatcher
    - GET, `/.well-known/openid-configuration`
  - OidcProviderConfigurationEndpointFilter
