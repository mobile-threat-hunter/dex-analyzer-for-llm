# androguard/dex-decompiler (Rust) 평가

**2026-09-08 · 단독으로 읽을 수 있게 작성.** 이 문서 하나로 배경·측정·결론이
전부 확인 가능해야 하며, 모든 수치는 재현 명령을 함께 적었다.

평가 대상은 `androguard/dex-decompiler` (Rust, Apache-2.0, v0.1.0)와 형제
프로젝트 넷(`dex-parser`, `dex-bytecode`, `axml-parser`, `yara-droid`)이다.
질문은 하나였다 — **이 도구가 dexllm에서 어떤 역할을 맡을 수 있는가.**

> **범위 주의.** 처리량·배율 비교는 **의도적으로 이 문서에 없다**(사용자 결정,
> 2026-09-08). 아래 판정은 어느 것도 속도에 근거하지 않으며, 근거는 메모리
> 안전성(§3)과 출력 정확성(§4)이다. 소요 시간·처리 건수 등 속도로 읽힐 수 있는
> 값은 §3에서도 전부 뺐다.

---

## 1. 결론 먼저

| 역할 | 판정 | 근거 |
|---|---|---|
| **런타임 의존성** | **불가** | 기본 모드가 메모리를 무한정 먹는다. 4.6 MB APK 하나에 **RSS 119 GB** |
| **테스트 오라클** | **불가** | 기본 모드가 `throw` 문을 삭제한다. 측정 대상을 지우는 오라클은 오라클이 아니다 |
| **아이디어 참고** | **가능, 범위 한정** | 디컴파일러 본체가 아니라 dexllm에 **없는** 표면 — taint solver, semgrep 엔진, 에뮬레이터 |

---

## 2. 왜 평가했고, 어떻게 시작됐나

androguard 진영이 Rust로 dex 처리 스택을 다시 쓰고 있다. dexllm은 C++ 코어 +
pybind11 래퍼에 DAD 정렬 디컴파일러를 내장한 구조라, 겹치는 영역이 크다.
평가 항목은 셋이었다 — 런타임으로 쓸 수 있나, 테스트 오라클로 쓸 수 있나(jadx가
이미 그 자리에 있다), 아니면 알고리즘만 참고할 것인가.

**평가 도중 이 도구가 개발 머신을 내려앉혔다.** 그 사고 자체가 첫 번째이자 가장
결정적인 측정치가 됐으므로 §3에 기록한다.

---

## 3. 메모리 — 기본 모드가 무한정 증가한다

### 3.1 실제로 일어난 일

2026-09-06 13:47:00, 세션과 백그라운드 태스크 넷이 같은 초에 죽었다. 커널 로그:

```
systemd-oomd invoked oom-killer: ... oom_score_adj=-900
oom-kill: constraint=CONSTRAINT_NONE, ..., global_oom,
          task_memcg=/user.slice/.../app.slice/app-gnome-code-13641.scope,
          task=dex-decompile, pid=1788679
Out of memory: Killed process 1788679 (dex-decompile)
          total-vm:161238004kB, anon-rss:119269648kB
```

**RSS 119 GB / 가상 161 GB, 123 GB 머신에서.** 입력은 4.6 MB APK 하나였다.

메커니즘은 오해하기 쉬워 정확히 적는다. 이 사고의 원인을 세 번 적었고 세 번
틀렸으며, 매번 로그 원문을 다시 읽어서 고쳤다:

- **systemd-oomd는 개입하지 않았다.** 유닛 로그가 완전히 비어 있다. 첫 줄의
  `systemd-oomd invoked oom-killer`는 "oomd가 메모리를 할당하려다 실패해 커널
  OOM killer가 발동했다"는 뜻이다.
- 죽인 주체는 **커널의 global OOM killer**(`CONSTRAINT_NONE, global_oom`)이고,
  **`dex-decompile` 하나만** 죽였다. 피해자 선택은 정확했다.
- **VS Code는 죽지 않았다.** 메인 프로세스가 살아남아 사후를 전부 로깅했다.
  죽은 건 **ptyHost**(`No ptyHost heartbeat after 6 seconds` →
  `ptyHost terminated unexpectedly`)이고, 통합 터미널의 모든 프로세스가 그
  자식이었다. 유휴 태스크까지 같은 초에 사라진 이유가 이것이다.

**따라서 결함은 killer의 정책이 아니라 cgroup 배치였다.** 폭주 프로세스가
편집기 자신의 scope(`app-gnome-code-<pid>.scope`) 안에서 돌고 있었다.
systemd-oomd를 더 공격적으로 설정했다면 **더 나빠졌을 것**이다 — oomd는 cgroup
단위로 죽이므로 희생자가 VS Code 전체였을 것이고, 커널은 오히려 폭주 프로세스만
골라 죽였다.

### 3.2 재현 — 스파이크가 아니라 무한 증가

`scripts/capped.sh`(전용 systemd scope + `MemoryMax`)로 상한을 씌우고 재현했다.

| 실행 형태 | 결과 |
|---|---|
| `-o /dev/null`, `restructure` | 상한 도달 → SIGKILL |
| `-d <dir>`, `restructure` | 상한 도달 → SIGKILL (중간까지만 쓰고 중단) |
| `-d <dir>`, `simple` | **완주** |

`-o /dev/null`의 출력 버퍼링 아티팩트가 아니다 — 클래스별 덤프에서도 같은 결과다.
**폭주는 restructure 패스 안에 있다.** 같은 입력·같은 출력 형식인데 `simple`은
완주하고 `restructure`는 상한에서 죽는다.

상한을 올려도 마찬가지였다(서로 다른 APK 두 개에서 각각 SIGKILL).
**상한을 올리는 것으로 해결되지 않는다.**

### 3.3 이 저장소가 취한 조치

- `scripts/capped.sh` — 외부 도구를 전용 systemd scope(`MemoryMax`,
  `MemorySwapMax=0`)에서 실행. 폭주하면 exit 137로 혼자 죽는다. systemd-run이
  없으면 rlimit 폴백.
- `.claude/uncapped-analyser-check.sh` — `PreToolUse(Bash)` 게이트. 저장소 밖의
  서드파티 빌드 산출물이나 known-heavy 이름을 **명령 위치에서** 실행하려 하면
  차단한다. 규칙을 적어두는 것과 강제되는 것은 다르다.

---

## 4. 정확성 — 기본 모드가 `throw` 문을 삭제한다

라인 수 차이만으로는 누락을 증명할 수 없다. 재구조화는 제어 흐름을 정당하게
합쳐 줄 수를 줄인다. **문장 단위 검증**이 필요하고, `throw`가 그 지표다 —
재구조화가 `throw`를 정당하게 없앨 수는 없다.

커밋된 fixture 중 하나는 **원본 Java 소스가 저장소에 함께 있어** 정답을 안다
(`tests/data/permissive-tls.java`, 이 프로젝트가 직접 작성한 fixture):

| 출처 | `throw` 개수 |
|---|---|
| 원본 Java 소스 | **5** |
| dexllm | **5** — 예외 타입과 메시지까지 정확 |
| dex-decompile `-m simple` | 5 (단 `throw ex0;`, 생성자 소실) |
| dex-decompile `-m restructure` (**기본값**) | **0** |

다른 fixture도 같다:

| fixture | restructure | simple |
|---|---|---|
| `invoke-custom.dex` | **0** | 13 |
| `method_handles.dex` | **1** | 11 |
| `permissive-tls.dex` | **0** | 5 |

**메모리를 터뜨리는 모드와 코드를 지우는 모드가 같은 모드이고, 메모리에 안전한
쪽은 예외 생성자를 잃는 쪽이다.**

---

## 5. 보안 탐지기

`--scan-vulns`는 여러 탐지기(인텐트 스푸핑, 동적 로딩 RCE, 안전하지 않은 로깅,
SQL, WebView, 하드코딩 시크릿, IPC)를 돌린다. 위 TLS fixture에 대해:

| | 결과 |
|---|---|
| dex-decompile `--scan-vulns` | **0건** |
| dexllm `detect_permissive_tls` | 10개 컴포넌트 보고, **4개 permissive**, 각각 이유 포함 |

dexllm은 음성 대조군 2개(`CheckingTrust`, `CheckingVerifier`)를 `not_proven`으로
남긴다 — 전부 플래그하는 게 아니다. permissive 판정 근거도 문장 단위다:
"`checkServerTrusted` 본문이 비어 있어 던질 수 없음", "`verify`가 상수 `true`를
반환".

---

## 6. 설계 — SSA와 타입 추론

두 가지를 직접 읽어 확인했다(경로는 실제 위치, 기억이 아님):

- **`src/decompile/ssa.rs` (483줄)** — SSA를 **이름 붙이기 전용**으로 쓴다.
  파일 자신의 주석이 그렇게 말한다: `/// Drop φ-nodes (Java cannot express
  them). Call after phi_canonical_map`. 즉 φ는 방출 전에 버려지고, 타입 추론의
  기반이 아니다.
- **`src/decompile/type_infer.rs` (1,305줄)** — **메서드 이름 하드코딩 테이블**
  이다: `"split" => "java.lang.String[]"`, `valueOf` → 박스 타입 등.

dexllm은 `IsAssignable`로 **dex의 실제 클래스 계층을 걷는다**(CLAUDE.md의
타입 추론 캐스케이드/미러/use-bound 계열 작업). 이름으로 추측하는 것보다
원리적으로 강하다. 이 축에서는 참고할 것이 없다.

---

## 7. 형제 프로젝트와 라이선스

| 프로젝트 | 라이선스 | 규모 | 비고 |
|---|---|---|---|
| `dex-decompiler` | Apache-2.0 | src 47,029줄 | 평가 대상 본체. PyO3 바인딩(`dex-decompiler-py`) 있음 |
| `dex-parser` | Apache-2.0 | 5,130줄 | |
| `dex-bytecode` | Apache-2.0 | 4,230줄 | |
| `axml-parser` | Apache-2.0 | 4,092줄 | Python `androguard/axml`의 포팅 |
| `yara-droid` | **GPL-3.0** | **854줄** | POC |

**다른 이슈에 미치는 영향:**

- **dexllm#82 (YARA)는 다시 열 필요 없다.** `yara-droid`는 GPL-3.0 854줄 POC라
  라이선스·성숙도 어느 쪽으로도 근거가 되지 않는다.
- **dexllm#54 (매니페스트 파싱)는 예상보다 싸다.** `axml-parser`는 Python
  `androguard/axml`의 포팅이고, **androguard 4.1.4가 이미 이 저장소의 venv에
  있다**(DAD 패리티 오라클로). PyPI에 `axml`·`pyaxml`도 있다. 진짜 질문은
  "어디서 구하나"가 아니라 **"런타임 의존성으로 승격할 것인가"** 다 — dexllm의
  런타임 의존성은 현재 `[ioc]` extra의 tldextract뿐이다.

---

## 8. 참고할 만한 것 — 디컴파일러가 아닌 표면

본체는 배제했지만, dexllm에 **없는** 기능이 있다. 아이디어 참고의 범위는 여기다:

- **`--taint-solve`** — Mariana-Trench 스타일 인터프로시저 taint solver
  (모델/새니타이저/전파/룰, SAPP 호환 JSON 출력)
- **`--scan-semgrep`** — 네이티브 semgrep 스타일 Android 룰 엔진
  (일반 Android + OWASP MASTG, SSA/value-flow + Java/XML 패턴)
- **`--emulate CLASS#METHOD`** — 메서드 에뮬레이터 (파라미터 지정, 스텝 실행,
  레지스터/힙 상태 출력)
- **`--scan-pending-intent`** — PendingIntent 생성 지점 스캐너

이들은 dexllm의 정적 xref/디컴파일 축과 겹치지 않는다. **코드를 가져오는 게
아니라 설계를 읽는 용도**다 — jadx를 테스트 오라클로만 쓰고 런타임에 넣지 않는
것과 같은 자세(embedded-only 정책).

---

## 9. 모든 수치의 재현 방법

```bash
B=~/Project/rust-dex-eval/dex-decompiler/target/release/dex-decompile

# 1) 메모리 무한 증가 — §3.2  (exit 137 = 상한 도달)
scripts/capped.sh 8G $B -i test_apk/APK/com.example.android.tvleanback.apk \
    -d /tmp/out -m restructure

# 2) throw 삭제 — §4
for m in restructure simple; do
  printf "%-12s %s\n" "$m" \
    "$(scripts/capped.sh 2G $B -i tests/data/permissive-tls.dex -m $m | grep -c 'throw ')"
done
grep -c "throw " tests/data/permissive-tls.java    # 정답: 5

# 3) 탐지기 — §5
scripts/capped.sh 2G $B -i tests/data/permissive-tls.dex --scan-vulns -o /dev/null
python -c "
import dexllm
r = dexllm.detect_permissive_tls(dexllm.DexKit('tests/data/permissive-tls.dex'))
print(len(r), 'components,', sum(1 for x in r if x['verdict']=='permissive'), 'permissive')"

# 4) 커널 OOM 기록 — §3.1
journalctl -k --since "2026-09-06" | grep -i "out of memory\|oom-kill"
journalctl -u systemd-oomd --since "2026-09-06"     # 비어 있음 = 개입 안 함
```

**외부 분석기는 반드시 `scripts/capped.sh`로 감싼다.** 게이트가 강제하며, 그
이유가 §3이다.

**로그 창에 주의.** §3.1의 사실관계는 처음에 `journalctl -k --since "6 hours
ago"`로 조회해 "커널 OOM 없음"이라고 잘못 결론냈다. 사건은 12시간 전이었다.
**부정 결과는 조회한 창만큼만 강하다.**

---

## 10. 미결 — 사용자 결정 사항

§1의 세 판정 중 **"아이디어 참고"의 실행 여부와 범위**가 열려 있다. 구체적으로:

1. §8의 네 표면 중 어느 것을 먼저 볼 것인가 (taint solver가 가장 크다)
2. dexllm#54를 androguard 런타임 의존성으로 풀 것인가, 자체 포팅할 것인가,
   계속 미룰 것인가

메모리·정확성 축은 측정으로 닫혔다. 처리량 축은 이 평가의 범위 밖이다.
