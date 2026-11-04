# deepseek-homegate

[DeepSeek Harness](https://github.com/deepseek-ai/DeepSeek-Harness)(DSH) 웹 표면을 **계정 로그인 + QR 기기 페어링**으로 보호하는 플러그인입니다. 24시간 도는 서버 한 대에 `dsh web`을 띄워두고, PC·노트북·폰이 같은 사설망(WireGuard/LAN)에서 편히 접속하는 상황을 목표로 합니다.

> **이 저장소는 두 오픈소스 플러그인의 구조를 연구한 뒤 새로 작성한 독립 구현입니다.**
> - [@xgone/dsh-remote](https://github.com/xgone/dsh-remote) (MIT) — 로그인 게이트, MFA, 그리고 코어의 `dsh-auth-*` 쿠키를 코어 자신의 비시로 재발행하는 방식(browser-auth v1 와이어 포맷 미러링)을 구조 참고했습니다.
> - [dsh-mini-remote](https://github.com/xingzhen199186/dsh-mini-remote) (MIT) — QR 페어링(1회용 grant → 장기 쿠키), 기기 명부, 모바일 원격 사용성 아이디어를 참고했습니다.
>
> 코드는 복사가 아니라 이 프로젝트의 요구(LAN/WG 전용, 단일 서버, 무중계)에 맞춰 직접 구현했으며, 두 상류 프로젝트의 라이선스(MIT)를 준수합니다.

## 왜 만드는가

DSH 웹 GUI는 기동 토큰 URL로 인증합니다. 재시작 때마다 토큰이 바뀌고, 새 기기마다 그 URL을 전해줘야 합니다. homegate는 이 절차를 없앱니다:

- **PC/노트북**: `http://서버:3080` → 계정+비번 로그인(30일 세션). 토큰을 다시는 보지 않습니다.
- **폰**: PC의 관리 페이지에서 QR 한 번 스캔 → 장기 기기 쿠키 발급 → 즉시 전체 GUI.
- 서버 재시작과 무관합니다. 인증서는 필요 없고, 사설망 전용입니다.

## 동작 방식

```
브라우저 ── hg_session / hg_device 쿠키 ──▶ [homegate 게이트] ── dsh-auth* 쿠키 주입 ──▶ DSH 코어 (webServer)
                                             │  미인증 HTML → 로그인 페이지
                                             │  미인증 API → 401 JSON
                                             │  미인증 WS upgrade → 즉시切断
```

1. **게이트**: 웹서버의 라우트 테이블(HTTP exact/prefix, WebSocket upgrade, SPA fallback)을 래퍼로 감쌉니다. 등록 완료 후의 신규 라우트도 래퍼를 통과합니다. 언인스톨/비활성 시 원래 핸들러를 복원합니다.
2. **코어 쿠키 재발행**: 게이트를 통과한 요청에 코어 `client-connection`이 영구 보관한 서명 비시(`client-connection/browser-session` 자격 레코드)로 코어 규격 `dsh-auth-<sha256(authority)>` 쿠키를 발행·주입합니다. `/api`, 스트림 WebSocket, 정적 SPA가 모두 코어 자체 인증을 통과 — 토큰 URL은 어떤 기기에도 전달되지 않습니다.
3. **QR 페어링 (`/mini`)**: 관리자 세션이 `/mini/invite`로 5분 1회용 grant + QR 생성 → 폰이 `/mini/p?g=…` 소모 → 기기 쿠키(기본 90일) 발급 → 명부 등록. 명부에서 철거하면 즉시 무효화.
4. **부트스트랩**: 계정이 비어 있으면 로그인 페이지가 첫 관리자 생성 폼을 표시하고, **루프백/바인드 주소 요청만** 허용합니다. 브라우저 없는 서버는 `bootstrap` 설정 블록으로도 생성 가능(1회용 — 첫 로그인 후 제거).

## 보안 포즈

- 비밀번호: scrypt(N=16384, r=8, p=1) 해시를 `$DSH_HOME/auth/homegate-store.json`(0600, 원자적 tmp+rename)에 저장. 평문 저장 지점 없음.
- 세션 쿠키: HMAC-SHA256 서명 `v1.<payload>.<sig>`, HttpOnly, SameSite=Lax, 만료. 서명 비시는 저장소에 영구화되어 재시작을 버팁니다.
- MFA: RFC 6238 TOTP(Google Authenticator/1Password/Bitwarden 호환) + 1회용 백업코드 10개. 코드 검증은 상수시간 비교.
- 속도제한: IP+사용자이름 고정 윈도우(기본 8회/15분), MFA 별도 카운터.
- 탈출구: `enabled: false`로 되돌리면 코어의 토큰 인증이 그대로 살아납니다. 계정 저장소는 그대로 두면 되살아납니다.

**명시적 비목표** — 인터넷 공개용 하드웨어링이 아닙니다. 모든 페어링 기기는 설계상 관리자급 접근을 얻습니다(원격 창 그 자체). 사설망 밖 노출 시 반드시 리버스 프록시+TLS를 앞에 두세요(`session.secure: true`).

## 설치

```bash
dsh plugin --profile web add github:ByungHyun21/deepseek-homegate
# 재시작 (패치 방식이라 필수)
systemctl --user restart dsh-web   # 또는 dsh --profile web 재기동
```

설치 후 [cordis.patch.yml](cordis.patch.yml)의 `homegate.config`을 필요에 따라 조정합니다:

| 설정 | 기본값 | 설명 |
|---|---|---|
| `enabled` | `true` | 게이트 전체 on/off (탈출구) |
| `session.ttlSeconds` | `2592000` | 세션/재발행 쿠키 수명 (30일) |
| `session.secure` | `false` | HTTPS 리버스 프록시 뒤에서는 `true` |
| `rateLimit.maxAttempts/windowMs` | `8 / 900000` | 로그인 속도제한 |
| `browserAuth.enabled` | `true` | 코어 쿠키 재발행 (끄면 코어 토큰 인증이 남음) |
| `mini.grantTtlMs` | `300000` | 페어링 QR 유효시간 |
| `mini.maxDevices` | `10` | 명부 용량 |
| `mini.deviceTtlDays` | `90` | 기기 쿠키 수명 |
| `bootstrap` | 없음 | 헤드리스 첫 관리자 사전 등록(평문 주의, 1회용) |

## 관리

`/auth/admin` (관리자 계정 로그인 후):
- 계정 목록/추가/삭제, 역할(user/admin/guest — **v1에서는 표기만 하고 전부 동일 권한**), 비밀번호 변경
- MFA 등록(Google Authenticator로 QR 스캔 → 코드 확인 → 백업코드 10회 표시)·해제
- 기기 명부: 이름(자동 추측: iPhone/Android/…), 철거, 새 페어링 QR

## 테스트

```bash
npm test   # node:test — 런타임 의존성 불필요 (schemastery/qrcode는 플러그인 로딩 시에만)
```

- `test/totp.test.mjs` — RFC 6238/4226 테스트 벡터
- `test/store.test.mjs` — scrypt 왕복, 파일 권한, 백업코드 소모, 명부
- `test/auth-cookie.test.mjs` — 코어 쿠키 v1 미러(서명/권한/만료/30일 캡), 게이트 쿠키, 스테일 쿠키 교체 시맨틱
- `test/gate.test.mjs` — 경로 분류, 속도제한 윈도우, 루프백 판정

## 로드맵 (v0.2+)

- **모바일 3뷰** — dsh-mini-remote 스타일의 전용 REST/SSE 레이어(단일 프레임/채팅/전체 + 승인·질문 카드). 현재 폰은 전체 GUI(데스크톱 레이아웃)를 사용합니다.
- 역할별 RPC 게이트 (`/api/remote.mux` 엔벨로프 단위 admin/user/guest 차등)
- HTTPS/PWA 매니페스트 (인증서 도입 후)
- `/auth/mfa/setup`의비밀번호 재확인 단계

## 라이선스 & 크레딧

MIT — [LICENSE](LICENSE). 구조 연구에 활용한 [@xgone/dsh-remote](https://github.com/xgone/dsh-remote)와 [dsh-mini-remote](https://github.com/xingzhen199186/dsh-mini-remote) 두 프로젝트의 MIT 라이선스에 감사를 표합니다. 이 저장소의 코드는 위 두 프로젝트에서 복사하지 않았습니다.
