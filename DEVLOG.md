# DEVLOG — форк airgeddon с фиксированным EAP challenge

Подробный журнал всех действий по задаче: форкнуть airgeddon и добавить к нему
пропатченный hostapd/hostapd-wpe, который при аутентификации генерит не
случайный, а фиксированный EAP challenge `1122334455667788` (повторённый до
нужной длины).

---

## 0. Итоговое ТЗ (после уточнений)

Перед стартом были заданы уточняющие вопросы. Согласованные решения:

- Патчим **и `hostapd`, и `hostapd-wpe`**.
- Фиксируем challenge для **всех EAP-методов** со случайным challenge
  (практически это EAP-MSCHAPv2 authenticator challenge и EAP-MD5 challenge).
- Значение 8 байт `11 22 33 44 55 66 77 88` **повторяется паттерном** до длины
  буфера (16 байт → `1122334455667788 1122334455667788`).
- Патченые бинари поставляются **локально в репе**, `airgeddon.sh`
  использует **только их** (изоляция от системных hostapd/hostapd-wpe, которые
  могут дёргать другие тулзы).
- Настоящий **форк с историей upstream** + мои коммиты сверху.
- Публикацию на GitHub делает пользователь сам (готовится локальный репозиторий).
- База сборки — **Kali source hostapd/hostapd-wpe 2.10** (см. п.3).

---

## 1. Разведка: как airgeddon использует hostapd

Рабочая директория была пустой; git не инициализирован.

Клонировал upstream во временную папку и изучил `airgeddon.sh`:

- Для **WPA Enterprise** (Evil Twin Enterprise) airgeddon вызывает бинарь
  `hostapd-wpe` и парсит его лог (`hostapd_wpe_log`), где лежат `username` +
  MSCHAPv2 challenge/response.
- Обычный `hostapd` используется для не-enterprise Evil Twin (PSK/OWE),
  `hostapd-mana` — отдельный инструмент.
- Значение `1122334455667788` — классический фиксированный 8-байтный DES-challenge
  для crack.sh (NetNTLMv1).

Ключевые места в `airgeddon.sh`:

- запуск: `command="hostapd-wpe \"${tmpdir}${hostapd_wpe_file}\""` (строка ~11851),
  `command="hostapd \"${tmpdir}${hostapd_file}\""` (строка ~11855);
- детект версий: `hostapd -v` (~17652), `hostapd-wpe -v` (~17660);
- детект наличия тулзов: `hash "${item}"` (~6958) — резолв через `PATH`;
- `scriptfolder` задаётся в `set_script_paths()`, которая вызывается из
  `initialize_script_settings()` — первой в `main()`, до любого детекта тулзов.

Вывод: достаточно подставить локальную папку с бинарями в начало `PATH` — это
покрывает и детект, и запуск, и проверку версии, не трогая систему.

## 2. Обследование окружения

- ОС: **Kali GNU/Linux Rolling 2025.4**, `gcc`/`make`/`git` присутствуют.
- `hostapd`/`hostapd-wpe` в системе не установлены.
- `gh` (GitHub CLI) не установлен → создать репу на GitHub из сессии нельзя,
  готовим локальный репозиторий.
- git identity: `pahuello <pahuello@gmail.com>`.
- Процесс работает в **user namespace** (файлы системы видны как `nobody`,
  реального root для `apt install`/`dpkg`/правки `/etc` нет).

## 3. Выбор базовой версии hostapd

- В Kali сейчас `hostapd 2.10` и `hostapd-wpe 2.10+git20220310`. Значение `2.12`
  в airgeddon — это лишь минимум для Wi-Fi7-фич, а не установленная версия.
- Upstream wpe-патч `OpenSecurityResearch/hostapd-wpe` заточен под **hostapd 2.6
  (2017)** и на 2.11/2.12 чисто не ложится — актуального wpe под 2.11/2.12 нет.
- Решение (согласовано): база — **Kali source 2.10**, максимально
  воспроизводимо на целевом Kali.

Источники, которые забрал:

- upstream tarball `hostapd-2.10.tar.gz` с `w1.fi`
  (sha256 `206e7c799b678572c2e3d12030238784bc4a9f82323b0156b4c9466f1498915d`);
- Kali-пакет `hostapd-wpe` c `gitlab.com/kalilinux/packages/hostapd-wpe`
  (ветка `kali/master`), из него `debian/patches/`:
  `hostapd-wpe.patch`, `kali-fixups.patch`, `Use-unsafe-openssl.patch`, `series`.

## 4. Анализ точек генерации challenge

В hostapd 2.10:

- `src/eap_server/eap_server_mschapv2.c`: `random_get_bytes(data->auth_challenge,
  CHALLENGE_LEN)` (CHALLENGE_LEN = 16) внутри `eap_mschapv2_build_challenge()`.
- `src/eap_server/eap_server_md5.c`: `random_get_bytes(data->challenge,
  CHALLENGE_LEN)` (CHALLENGE_LEN = 16) внутри `eap_md5_buildReq()`.

Проверил, что Kali-`hostapd-wpe.patch` меняет `eap_server_mschapv2.c`, но
**не трогает** строку `random_get_bytes` и вообще не трогает `eap_server_md5.c`.
Значит один и тот же diff корректно ложится и на vanilla, и на wpe-дерево.

Прочие EAP-методы со «случайностью» (EAP-PWD/PSK/PAX/SAKE/GPSK) — это не
challenge/response хэши для крекинга, их трогать не нужно; фикс только для
MSCHAPv2 и MD5.

## 5. Патч фиксированного challenge

`custom_hostapd/patches/fixed-eap-challenge.patch`. В обоих файлах:

- добавлен статический паттерн и хелпер:
  ```c
  static const u8 ag_fixed_challenge_pattern[8] = {
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
  };
  static void ag_fill_fixed_challenge(u8 *buf, size_t len) {
      size_t i;
      for (i = 0; i < len; i++)
          buf[i] = ag_fixed_challenge_pattern[i % sizeof(ag_fixed_challenge_pattern)];
  }
  ```
- вызов `random_get_bytes(...)` для challenge заменён на
  `ag_fill_fixed_challenge(...)` (в MSCHAPv2 — под условием
  `!data->auth_challenge_from_tls`).

Diff сгенерирован через `diff -u` с префиксами `a/`,`b/`, чтобы применялся
`patch -p1` / `git apply` на оба дерева. Никакая другая случайность не тронута.

## 6. Зависимости сборки (обход user namespace)

- `openssl` dev в системе есть (OpenSSL 3.5.4, `ssl.h` на месте).
- `libnl-3-dev`/`libnl-genl-3-dev` отсутствовали.
- `apt install`/`apt-get download` не работают: user namespace ломает
  drop-privileges у apt (`setgroups/seteuid failed`).

Обход: скачал `.deb` напрямую из пула Kali
(`http://http.kali.org/kali/pool/main/libn/libnl3/`, версия `3.12.0-2+b1`,
amd64: `libnl-3-dev`, `libnl-genl-3-dev`, `libnl-3-200`, `libnl-genl-3-200`) и
распаковал в локальный sysroot `/tmp/sysroot` через `dpkg-deb -x`.

Для локальной сборки против sysroot использовал:
`PKG_CONFIG_PATH`, `PKG_CONFIG_SYSROOT_DIR`, `LIBRARY_PATH` (иначе линкер не
находил `-lnl-3`). На целевом Kali это не нужно — там libnl в системных путях.

## 7. Сборка и найденные грабли

Обычный hostapd:
- extract → `patch -p1 fixed-eap-challenge.patch` → `cp hostapd/defconfig
  hostapd/.config` → `make -C hostapd hostapd`. Мой C-код компилируется без
  ошибок; бинарь линкуется на системные `libnl`/`libssl`.

hostapd-wpe — по ходу вылезли и решены проблемы:

1. **Цель make.** `kali-fixups.patch` переименовывает выходные бинари; правильная
   цель — `hostapd-wpe` (а не `hostapd`), бинарь `hostapd/hostapd-wpe`.
2. **openssl-unsafe.** Сначала при ручной сборке я применил все три Kali-патча,
   и дерево стало ссылаться на пакет `openssl-unsafe` (`<openssl-unsafe/...>`,
   `-lunsafessl`/`-lunsafecrypto`) — это Kali-специфичный OpenSSL с legacy-алго.
   Разобрался: эти ссылки вносит именно `Use-unsafe-openssl.patch` (он применялся
   частично, а не был пропущен целиком). Сам `hostapd-wpe.patch`+`kali-fixups.patch`
   дают **штатный** OpenSSL (0 совпадений `openssl-unsafe`).
3. **Legacy-провайдер.** Проверил `src/crypto/crypto_openssl.c`: hostapd 2.10 сам
   вызывает `openssl_load_legacy_provider()`, а в системе есть
   `/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so`. Значит MD4/DES для
   MSCHAPv2 работают со **штатным** OpenSSL 3.

Итоговое решение: **не применять** `Use-unsafe-openssl.patch`. Тогда
hostapd-wpe собирается со стандартным OpenSSL, зависит только от
`libssl.so.3`/`libcrypto.so.3`/`libnl` (всё есть в Kali из коробки), пакет
`openssl-unsafe` не нужен.

Результат сборки: `hostapd v2.10` и `hostapd-WPE v2.10` (последнее совпадает с
регэкспом детекта версии в airgeddon: `^hostapd-WPE v\K[0-9]+\.[0-9]+`).
Бинари застриплены.

## 8. build.sh

`custom_hostapd/build.sh` воспроизводит рабочую сборку:

- проверяет/ставит зависимости (`apt-get` при запуске от root на Kali/Debian);
- сверяет sha256 вендоренного tarball;
- собирает обычный hostapd (fixed-challenge patch + defconfig);
- собирает hostapd-wpe (`hostapd-wpe.patch` + `kali-fixups.patch` +
  fixed-challenge patch; **без** Use-unsafe-openssl);
- кладёт и стрипает `bin/hostapd`, `bin/hostapd-wpe`.

Прогон начисто: `EXIT=0`, обе цели собраны.

## 9. Интеграция в airgeddon

В конце `set_script_paths()` (после установки `scriptfolder`) добавлен блок:

```bash
custom_hostapd_bindir="${scriptfolder}custom_hostapd/bin"
if [ -x "${custom_hostapd_bindir}/hostapd" ] || [ -x "${custom_hostapd_bindir}/hostapd-wpe" ]; then
    export PATH="${custom_hostapd_bindir}:${PATH}"
fi
```

Проверки: `bash -n airgeddon.sh` — синтаксис ок; с подставленным PATH
`command -v hostapd`/`hostapd-wpe` резолвятся в `custom_hostapd/bin`.

## 10. Документация и git

- Добавлены `custom_hostapd/README.md` и корневой `FORK_NOTES.md`.
- `custom_hostapd/build.sh` сделан исполняемым.
- Проверено, что `.gitignore` не игнорирует новые файлы.
- Всё закоммичено поверх истории upstream (родитель — upstream merge-commit),
  один коммит:
  `Add patched hostapd/hostapd-wpe with fixed EAP challenge (1122334455667788)`
  (11 файлов, +4731).

Замечание по окружению: переименование remote (`origin`→`upstream`) в этой
сессии не прошло — запись в `.git/config` заблокирована (`Device or resource
busy`, вероятно держит git-интеграция IDE). `git add`/`commit` (пишут в
index/objects) работают. Смену remote и `git push` пользователь делает в своём
обычном терминале.

## 11. Фикс: недостающая зависимость libsqlite3-dev

При запуске `build.sh` на «чистом» Kali сборка `hostapd-wpe` упала на
`fatal error: sqlite3.h: No such file or directory`. Причина: wpe-конфиг
(`hostapd/.config` из wpe-патча) содержит `CONFIG_SQLITE=y`, из-за чего
`src/ap/hostapd.h` тянет `<sqlite3.h>`. В моей песочнице `sqlite3.h` был
предустановлен, поэтому раньше не всплыло; обычный hostapd (defconfig) sqlite не
использует и собирался нормально.

Исправление: в `maybe_install_deps` (`build.sh`) добавлен `libsqlite3-dev`
(и в apt-список, и в проверку `[ -e /usr/include/sqlite3.h ]`, и в текст ручной
установки). Рантайм-библиотека `libsqlite3.so.0` есть на стандартном Kali, так
что готовый бинарь запустится без доустановки. После фикса `build.sh`
собирает обе цели, `EXIT=0`.

## 12. Тест на железе и откат патча

При тесте на реальном адаптере (Alfa AWUS036ACH, wlan1) клиент прошёл
EAP-MSCHAPv2, но hostapd-wpe залогировал **случайный** 8-байтный
`challenge: fb:88:6b:05:87:38:f5:e5`, а не фиксированный `11:22:...`.

Причина (подтверждена кодом wpe-патча в `eap_server_mschapv2.c`):
```
challenge_hash(peer_challenge, data->auth_challenge, username, username_len, wpe_challenge_hash);
wpe_log_chalresp("mschapv2", ..., wpe_challenge_hash, 8, nt_response, 24);
```
В лог пишется `ChallengeHash = SHA1(PeerChallenge ‖ AuthChallenge ‖ Username)[:8]`.
Мы зафиксировали только `AuthChallenge`, а `PeerChallenge` клиент генерит
случайно и присылает уже после нашего challenge, поэтому итоговый 8-байтный
challenge остаётся случайным. Подогнать SHA1 под нужное значение нельзя.

Вывод: цель пользователя — инстант-таблица crack.sh (`1122334455667788`) для
WPA-Enterprise — **недостижима by design**. Фиксированный 8-байтный challenge
идёт напрямую в ответ только там, где нет peer challenge: SMB/NetNTLMv1
(Responder), PPTP/MS-CHAPv1, Cisco LEAP (в hostapd EAP-сервере не реализован).
Для EAP-PEAP/TTLS-MSCHAPv2 challenge всегда производный.

Это ровно тот нюанс «8 vs 16 байт», о котором предупреждалось на этапе
уточнения ТЗ (п.0).

Решение пользователя: **откатить патч** (он для этой цели бесполезен). Форк
сброшен к чистому upstream (`git reset --hard 6f453c1`): удалены
`custom_hostapd/`, `FORK_NOTES.md` и правка `airgeddon.sh`; коммиты
`27ef8d4`/`1be91b6` отброшены (доступны через `git reflog`). Практические
альтернативы для добычи кред из WPA-Enterprise: crack.sh полным перебором DES по
фактическому challenge, `hashcat -m 5500`, либо смена вектора на EAP-TTLS/PAP или
EAP-GTC (плейнтекст-пароль).

## Что осталось на пользователя / вне песочницы

- **Живой тест «в эфире»** (реальный клиент, проверка challenge в wpe-логе/хэше)
  — нужен Wi-Fi-адаптер и root, в песочнице невозможно. Проверены компиляция,
  применимость патча, запуск бинарей, версии, резолв PATH.
- **Публикация на GitHub** — `gh` не установлен; пуш делает пользователь.
- **Сертификаты hostapd-wpe** для Enterprise-атаки (стандартный
  `/etc/hostapd-wpe/certs/` или свой путь) — вне патча.

## Полезные пути в репозитории

```
custom_hostapd/
├── bin/{hostapd,hostapd-wpe}                 # готовые патченые бинари (x86_64)
├── patches/
│   ├── hostapd-wpe.patch                      # Kali wpe patch (2.10)
│   ├── kali-fixups.patch                      # Kali FHS/path fixups
│   └── fixed-eap-challenge.patch              # этот форк: фикс challenge
├── src/{hostapd-2.10.tar.gz,*.sha256}         # вендоренный upstream
├── build.sh                                   # пересборка из исходников
└── README.md
FORK_NOTES.md                                  # краткое описание форка
DEVLOG.md                                      # этот файл
```
