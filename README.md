# openwrt-t5004

ipTIME T5004 전용 커스텀 OpenWrt 빌드 레시피와 펌웨어 릴리스입니다. 이 저장소에는 **빌드 레시피만** 들어 있고, 완성된 이미지는 [Releases](https://github.com/debpolaris/openwrt-t5004/releases)에 있습니다.

**받는 사람용 요약**: Releases에서 `*-squashfs-sysupgrade.bin`과 `SHA256SUMS`를 내려받아 `sha256sum -c SHA256SUMS`로 확인한 뒤, **현장에서 LAN으로 접속해** `sysupgrade -n`으로 설치하십시오. 원격 플래시는 지원하지 않는 시나리오입니다(아래 이유). 설치 후 기본 구성은 `clean_after` 스크립트 묶음을 사용합니다.

## 왜 공식 OpenWrt 대신 커스텀 빌드인가

- **커널 보안 패치**: 공식 25.12.4의 커널은 6.12.87이고, CVE-2026-98432 수정은 6.12.113 이후에 들어갑니다. 이 빌드는 **Linux 6.12.116**이며 수정 내용(`net/ipv4/af_inet.c`, `net/ipv4/tcp_ipv4.c`의 `kfree_rcu` 변경)을 빌드 시 소스 수준에서 검증합니다.
- **재현 가능성**: OpenWrt 본체와 4개 피드, AWG 소스를 커밋 해시로 고정(`config/sources.json`)합니다. 같은 레시피 → 같은 이미지.
- **AmneziaWG 선택 제공**: 공식 저장소에 없는 AWG 커널 모듈/도구를 이 커널과 일치하는 버전으로 빌드해 **선택 패키지**로 동봉합니다. 기본 이미지에는 설치하지 않습니다.
- **불필요한 서비스 제외**: `microsocks`와 `luci-proto-amneziawg`는 빌드 설정에서 명시적으로 제외합니다.
- **자격증명 비 embed**: 이미지에 SSH 키·비밀번호 해시·개인키가 없음을 빌드 시 검사합니다.

## 현재 릴리스

[`v25.12-k6.12.116-60c494ad`](https://github.com/debpolaris/openwrt-t5004/releases/tag/v25.12-k6.12.116-60c494ad) (prerelease)

- OpenWrt 25.12-SNAPSHOT, revision `custom-60c494ad065f`, target `ramips/mt7621`, device `iptime,t5004`
- Linux 6.12.116, WireGuard 포함, AWG 선택 모듈, 패키지 129개
- **실기기 부팅·네트워크 테스트는 하지 않았습니다.** prerelease로 표시하는 이유입니다.
- 알려진 제한: VLAN-aware bridge STP 사용 전 [OpenWrt issue 25457](https://github.com/openwrt/openwrt/issues/25457) 검토.

## 설치

```sh
# 현장에서 LAN 접속 후, 설정 전부 삭제하고 설치
sysupgrade -n /tmp/openwrt-ramips-mt7621-iptime_t5004-squashfs-sysupgrade.bin
```

- **원격 플래시 금지 사유**: 이미지에는 openssh-server가 없고 기본 dropbear는 자격증명이 없습니다. 접속이 끊기면 원격으로 복구할 수단이 없습니다. T5004에는 원격 콘솔이 없습니다.
- 설정 유지 업그레이드를 하더라도 `/root/.ssh/authorized_keys`와 `/root`의 스크립트는 기본 보존 대상이 아닙니다. `/etc/sysupgrade.conf`에 보존 목록을 명시하십시오.
- `*-initramfs-kernel.bin`은 플래시 없이 RAM으로 부팅해 테스트/복구할 때 씁니다.
- 커널 멤버는 3.43 MiB로 T5004의 4 MiB 커널 파티션 이내임을 확인했습니다.

## 설치 후 기본 구성 (`clean_after`)

별도로 관리하는 `clean_after` 스크립트 묶음으로 초기 구성합니다.

1. `01-t5004-clean-init-base.sh` — 패키지, dropbear, DDNS, banIP, watchcat, 네트워크/방화벽
2. `02-t5004-wireguard-keygen.sh` — 라우터/클라이언트 키 생성
3. `03-t5004-wireguard-setup.sh` — WireGuard 터널과 전달 규칙
4. 재부팅 1회
5. `04-t5004-post-reboot-check.sh` — 읽기 전용 검증

목표 정책: **WAN SSH는 공개키 전용(root 허용), 내부(LAN·WireGuard)는 비밀번호+공개키**. dropbear는 섹션 단위로 인증이 갈리므로 `internal`/`wan` 두 섹션으로 구성합니다. WireGuard는 기본 구성 후 별도로 구성하며, 클라이언트는 **클라우드 서버용**과 **일반 사용자용**으로 키·주소를 분리해 관리할 예정입니다.

### 이 펌웨어와 스크립트 사이의 주의점

- **kmod ABI**: 이 이미지의 커널은 6.12.116이고 공식 25.12.4 저장소의 kmod는 다른 ABI입니다. kmod 계열은 공식 저장소에서 설치하지 말고 릴리스의 `matching-packages.tar.zst` + `package-public-keys/`를 사용하십시오. WireGuard kmod는 이미지에 이미 있으므로 스크립트의 중복 설치 줄은 검토 대상입니다.
- **owut / attended sysupgrade**: 공식 ASU 서버는 이 커널 패치를 모르는 이미지를 만듭니다. 업그레이드는 이 저장소 CI로 재빌드하십시오.
- 스크립트와 이 펌웨어의 호환성 검토는 별도로 진행 중입니다. 검토 결과에 따라 스크립트가 수정될 수 있습니다.

## 선택: AmneziaWG 설치

```sh
mkdir -p /tmp/awg-repo /tmp/awg-keys
tar -xf /tmp/matching-packages.tar.zst -C /tmp/awg-repo
cp /tmp/package-public-keys/* /tmp/awg-keys/
apk add --keys-dir /tmp/awg-keys \
  --repository file:///tmp/awg-repo/packages \
  --repository file:///tmp/awg-repo/targets/ramips/mt7621/packages \
  kmod-amneziawg amneziawg-tools
```

개별 `.apk` 파일은 서명이 없으므로 반드시 번들 서명 저장소를 통해 설치하십시오.

## 검증 상태

CI(`scripts/collect.py`, `scripts/verify.py`)와 독립 재검증으로 확인한 것:

- `SHA256SUMS` 전체 일치, `profiles.json` 해시와 실제 이미지 일치
- sysupgrade `CONTROL`/uImage/SquashFS 구조, 커널 파티션 크기 적합
- 메타데이터 `compat_version 1.1`, 지원 기기 `iptime,t5004`
- 매니페스트에 WireGuard 존재, AWG·microsocks 부재
- 커널 소스의 CVE 수정 존재, 컴파일된 `UTS_RELEASE` = 6.12.116
- 이미지에 자격증명/개인키 없음, 선택 패키지 설치 시뮬레이션 통과

확인하지 않은 것: 실기기 부팅, 무선/유선 네트워크 동작, WireGuard 실터널, 장기 안정성.

## 빌드 재현

GitHub Actions 워크플로 `Build T5004 firmware`를 `workflow_dispatch`로 실행합니다. hosted runner에서 핀된 소스를 받아 빌드하고, 검증 후 `dist/`를 아티팩트로 올립니다(90일 보존). 성공하면 `v25.12-k<kernel>-<openwrt-commit12>-<recipe-commit12>` 태그의 **prerelease**를 자동 생성하고 펌웨어·선택 패키지·검증 파일·대응 소스를 Release 자산으로 업로드합니다.

```
config/sources.json   # 핀된 커밋/버전
config/t5004.config   # 빌드 설정(대상 기기, WireGuard, AWG=m, 제외 목록)
scripts/prepare.py    # 소스 준비
scripts/build.sh      # 빌드
scripts/verify.py     # 설정/커널 검증
scripts/collect.py    # 이미지/매니페스트/소스 검증과 수집
```

## 소스 제공 (GPL)

릴리스의 `corresponding-source.tar.zst`에 빌드 트리의 대응 소스가, `build-recipe.tar.zst`에 레시피 사본이 포함됩니다.

## 라이선스

[LICENSE](LICENSE)를 따릅니다. OpenWrt 및 포함 패키지의 라이선스는 각 상위 프로젝트를 따릅니다.
