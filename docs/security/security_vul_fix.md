# Fix HIGH/CRITICAL vulnerabilities in the `dbctl` image

Mục tiêu: loại bỏ toàn bộ lỗ hổng mức **HIGH** và **CRITICAL** mà Trivy phát hiện trong image
`quay.io/kubeblocks/apecloud/dbctl:0.1.8`, mà không đổi logic code. Sau khi fix, image vẫn build
bằng Podman và được quét lại bằng Trivy để xác nhận.

## 1. Hiện trạng trước khi fix

```bash
trivy image quay.io/kubeblocks/apecloud/dbctl:0.1.8 --severity HIGH,CRITICAL
```

Kết quả: **19 lỗ hổng** trên layer Alpine (17 HIGH, 2 CRITICAL) và **35 lỗ hổng** trên Go binary
`bin/dbctl` (31 HIGH, 4 CRITICAL). Chia làm 2 nhóm nguyên nhân:

| Nhóm | Nguyên nhân | Package/Module liên quan |
|---|---|---|
| OS packages (Alpine) | base image `alpine:3.22.1` đã cũ, các package OpenSSL/musl/zlib có patch mới hơn | `libcrypto3`, `libssl3`, `musl`, `musl-utils`, `zlib` |
| Go binary | các Go module phụ thuộc (transitive) bị "đóng băng" version cũ trong `go.sum`, và Go toolchain (`1.23.10`) chưa có patch cho các CVE của `crypto/tls`, `net/url`, `crypto/x509` | `github.com/jackc/pgx/v5`, `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/oauth2`, `google.golang.org/grpc`, Go `stdlib` |

## 2. Cách fix

### 2.1. Nâng cấp các Go module bị lỗi

Trong thư mục `dbctl/`, dùng `go get` để kéo lên version đã có fix cho từng CVE (xem cột "Fixed
Version" trong báo cáo Trivy), rồi `go mod tidy` để đồng bộ `go.sum` và các dependency gián tiếp:

```bash
cd dbctl
go get github.com/jackc/pgx/v5@v5.10.0
go get golang.org/x/crypto@v0.53.0
go get golang.org/x/net@v0.56.0
go get golang.org/x/oauth2@v0.36.0
go get google.golang.org/grpc@v1.81.1
go mod tidy
```

`go mod tidy` tự kéo theo các bản vá liên quan (`golang.org/x/sys`, `x/text`, `x/tools`,
`google.golang.org/protobuf`, `go.opentelemetry.io/otel`, ...) và **tự bump directive `go` trong
`go.mod` từ `1.23.0` lên `1.25.0`** — điều này là cần thiết vì các CVE của `stdlib`
(`crypto/tls`, `net/url`, `crypto/x509`, `net/mail`, `mime`) chỉ được vá từ Go `1.24.x`/`1.25.x`
trở đi.

Sau khi nâng cấp, build + test lại để chắc chắn không có breaking change về API:

```bash
go build ./...
go vet ./...
go test ./...
```

> Trong môi trường thực hiện task này, tất cả test pass, không có breaking change.

### 2.2. Cập nhật `Dockerfile` (`docker/Dockerfile`)

Hai thay đổi:

1. **Bump Go toolchain dùng để build binary**, để binary được build bằng compiler đã vá lỗi
   `stdlib`, đồng thời khớp với `go.mod` (`go 1.25.0`):

   ```diff
   -ARG GO_VERSION=1.23.10-alpine
   +ARG GO_VERSION=1.25-alpine
   ```

2. **Vá các package OS của Alpine** bằng cách chạy `apk update && apk upgrade` ngay trong stage
   `dist` (alpine:3.22), để lấy bản vá mới nhất của `libcrypto3`, `libssl3`, `musl`, `zlib` mà
   không cần đợi Alpine ra point-release mới:

   ```diff
    FROM docker.io/alpine:3.22 as dist
    ARG APK_MIRROR

   +# Pull latest patched packages to pick up fixes for known CVEs in the base image
   +# (libcrypto3/libssl3/musl/musl-utils/zlib) without waiting for a new Alpine point release.
   +RUN apk update && apk upgrade --no-cache
   +
    COPY --from=builder /out/dbctl /bin

    USER 65532:65532
   ```

### 2.3. Build lại image bằng Podman

```bash
cd dbctl
podman build --isolation=chroot -t dbctl:fixed -f docker/Dockerfile .
```

> Lưu ý: trong môi trường sandbox/rootless không có quyền truy cập
> `/proc/sys/net/ipv4/ping_group_range`, Podman mặc định dùng isolation kiểu container
> (`crun`) sẽ báo lỗi `Permission denied`. Thêm `--isolation=chroot` để build không cần tạo
> network namespace riêng. Trên máy CI/host bình thường (không sandbox), có thể bỏ flag này.

### 2.4. Quét lại bằng Trivy để xác nhận

Podman image cục bộ không có sẵn socket cho Trivy truy cập trực tiếp, nên export ra tar trước:

```bash
podman save -o /tmp/dbctl-fixed.tar localhost/dbctl:fixed
trivy image --severity HIGH,CRITICAL --input /tmp/dbctl-fixed.tar
```

Kết quả sau khi fix:

```
┌────────────────────────────┬──────────┬──────────────────┬─────────┐
│           Target           │   Type   │ Vulnerabilities  │ Secrets │
├────────────────────────────┼──────────┼──────────────────┼─────────┤
│ dbctl-fixed.tar (alpine)   │  alpine  │        0          │    -    │
├────────────────────────────┼──────────┼──────────────────┼─────────┤
│ bin/dbctl                  │ gobinary │        0          │    -    │
└────────────────────────────┴──────────┴──────────────────┴─────────┘
```

→ **0 HIGH, 0 CRITICAL** trên cả layer OS và Go binary (từ 19 + 35 = 54 ban đầu).

Một lần quét full severity (không filter) cho thấy chỉ còn 3 lỗ hổng LOW/MEDIUM còn sót lại
(`filippo.io/edwards25519`, `github.com/redis/go-redis/v9`, `go.mongodb.org/mongo-driver`) —
nằm ngoài phạm vi yêu cầu (chỉ fix HIGH/CRITICAL) nên không cần xử lý ở bước này.

## 3. Lỗi phát sinh khi triển khai thực tế: `Init:Error` trên cluster Redis

Sau khi đẩy image `fixed` vào cluster KubeBlocks thật, pod Redis-cluster bị `Init:Error`:

```
cp: can't stat '/config': No such file or directory
```

**Nguyên nhân:** `ComponentDefinition` của redis-cluster
(`addons/redis/templates/cmpd-redis-cluster.yaml:520-526`) hard-code init container `init-dbctl`
chạy lệnh:

```
cp -r /bin/dbctl /config /tools/
```

Image gốc `quay.io/kubeblocks/apecloud/dbctl:0.1.8` chứa **hai** thứ ở root: `/bin/dbctl` và một
thư mục `/config/dbctl/...` (vài file YAML tĩnh kiểu Dapr/probe legacy — không phải code, không
liên quan tới CVE nào). `Dockerfile` trong repo này lại chưa từng `COPY` thư mục `/config` đó —
image gốc 0.1.8 phải được build bằng một pipeline khác có thêm bước đóng `/config` vào. Khi build
lại image theo đúng `Dockerfile` hiện có, image mới thiếu `/config` → lệnh `cp` trong init
container fail → pod đứng ở `Init:Error`.

**Cách fix:** thêm một build stage lấy `/config` từ image 0.1.8 đã publish trước đó và copy nó
sang image mới, giữ nguyên toàn bộ các bản vá CVE đã làm ở mục 2:

```diff
+# KubeBlocks ComponentDefinitions (e.g. addons/redis) run a hard-coded init container
+# `cp -r /bin/dbctl /config /tools/` against this image, so /config must exist even
+# though nothing in this repo's build produces it. Pull it from the previously published
+# image so it survives the CVE-driven rebuild below.
+FROM quay.io/kubeblocks/apecloud/dbctl:0.1.8 AS legacy-config
+
 # Use alpine with tag 20230329 ...
 FROM docker.io/alpine:3.22 as dist
 ARG APK_MIRROR

 RUN apk update && apk upgrade --no-cache

 COPY --from=builder /out/dbctl /bin
+COPY --from=legacy-config /config /config

 USER 65532:65532
```

Build lại, kiểm tra `/config` đã có trong image, và quét lại Trivy để chắc rằng việc copy thêm
layer cũ không kéo theo CVE HIGH/CRITICAL nào (kết quả vẫn 0/0 — vì `/config` chỉ là YAML tĩnh).

## 4. Lỗi phát sinh lần 2: `cluster ... Failed` — `Role probe timeout`

Sau khi fix `/config`, pod chạy được (`3/3 Running`) nhưng `kubectl get cluster` báo
`phase: Failed`, lý do `Role probe timeout, check whether the application is available`.
Log của container `kbagent` cho thấy:

```
exit code: 255, stderr: Error: unknown flag: --config-path
Usage:
  dbctl database getrole [flags]
```

**Nguyên nhân — đây là lỗi có sẵn trên `main`, không phải do việc nâng cấp CVE gây ra:**
`addons/redis/templates/cmpd-redis-cluster.yaml` (và `cmpd-redis.yaml`) hard-code lệnh probe role:

```
/tools/dbctl --config-path /tools/config/dbctl/components redis getrole
```

nhưng `dbctl/ctl/ctr.go` ở `main` không đăng ký flag `--config-path` nữa. So sánh với binary đã
publish (`quay.io/kubeblocks/apecloud/dbctl:0.1.8`, chạy `--help`) thì flag này **có tồn tại**
(default `/tools/config/dbctl/components/`). Lùi git history của repo `dbctl` tìm thấy commit
`9c9abec` ("fix", đã merge vào `main` từ trước, không liên quan gì đến việc nâng cấp CVE lần này)
đã xoá việc đăng ký `--config-path` (và `--disable-dns-checker`) ở `ctl/ctr.go`, dù `configDir`
chưa từng được dùng ở đâu trong logic Go — chỉ gán biến rồi bỏ. Helm chart `addons/redis` vẫn
truyền flag này nên cobra reject ngay từ bước parse flag → probe luôn fail → KubeBlocks coi shard
không xác định được role → cluster `Failed`.

→ Nói cách khác: source code `dbctl` trên `main` đã lệch (regress) so với binary 0.1.8 đã publish
từ trước khi tôi bắt đầu vá CVE; lỗi chỉ lộ ra vì đây là lần đầu tiên ai đó build lại `dbctl` từ
source và deploy thật.

**Cách fix:** thêm lại đúng flag `--config-path` ở `dbctl/ctl/ctr.go` (no-op, chỉ để cobra chấp
nhận, không phục hồi logic nào khác đã bị refactor):

```diff
 var opts = kzap.Options{
 	Development: true,
 }
+
+// configDir is unused by current dbctl logic, but the flag must stay registered:
+// KubeBlocks ComponentDefinitions (e.g. addons/redis) hard-code `dbctl --config-path ...`
+// on the CLI invocation, and cobra errors out with "unknown flag" if it's not declared.
+var configDir string
 ...
 	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
+	RootCmd.PersistentFlags().StringVar(&configDir, "config-path", "/tools/config/dbctl/components/", "dbctl default config directory for builtin type")
 	err := viper.BindPFlags(pflag.CommandLine)
```

Build lại (`dbctl:fixed3`), xác nhận `dbctl --help` có lại `--config-path`, và quét Trivy lần
cuối — vẫn 0 HIGH/0 CRITICAL.

## 4b. Dọn lại cách lấy `/config`: bỏ phụ thuộc vào image cũ

Cách ở mục 3 (`FROM quay.io/kubeblocks/apecloud/dbctl:0.1.8 AS legacy-config`) hoạt động đúng,
nhưng về logic thì kỳ — image đang được vá lỗi lại phải `FROM` chính image cũ (đầy lỗ hổng) để
lấy 1 thư mục tĩnh, và build sẽ luôn phụ thuộc quay.io còn giữ tag `0.1.8` hay không.

Vì `/config/dbctl/...` chỉ là 12 file YAML tĩnh (~2KB, không phải binary/code), cách sạch hơn là
trích xuất **một lần** rồi commit thẳng vào repo, sau đó `COPY` từ build context như file thường:

```bash
podman save -o /tmp/dbctl-orig.tar quay.io/kubeblocks/apecloud/dbctl:0.1.8
mkdir -p /tmp/orig-extract && tar xf /tmp/dbctl-orig.tar -C /tmp/orig-extract
# tìm layer chứa /config, giải nén nó
tar xf /tmp/orig-extract/<layer>.tar config/ -C dbctl/docker/
```

Kết quả: `dbctl/docker/config/dbctl/{config.yaml,components/*.yaml}` được commit vào repo, và
Dockerfile chỉ còn:

```diff
 COPY --from=builder /out/dbctl /bin
-COPY --from=legacy-config /config /config
+# KubeBlocks ComponentDefinitions (e.g. addons/redis) run a hard-coded init container
+# `cp -r /bin/dbctl /config /tools/` against this image, so /config must exist even
+# though dbctl's own build doesn't produce it (legacy probe/binding config, static YAML
+# only, vendored from the previously published image — see docker/config/).
+COPY docker/config /config
```

Không còn `FROM quay.io/kubeblocks/apecloud/dbctl:0.1.8` trong Dockerfile nữa — build không phụ
thuộc vào image cũ, không cần pull lại nó mỗi lần build, và không còn nhìn "ngược logic". Build
lại (`dbctl:fixed4`) và Trivy vẫn 0 HIGH/0 CRITICAL.

## 5. File đã thay đổi

- `dbctl/go.mod`, `dbctl/go.sum` — nâng version các module và Go directive (`1.23.0` → `1.25.0`).
- `dbctl/docker/Dockerfile` — bump `GO_VERSION` build arg, thêm `apk upgrade` trong stage `dist`,
  `COPY docker/config /config` để khôi phục `/config` mà runtime của KubeBlocks cần.
- `dbctl/docker/config/` (mới) — vendor lại các file YAML tĩnh từ image 0.1.8 (không phải code,
  không liên quan CVE) để Dockerfile không còn phụ thuộc vào image cũ khi build.
- `dbctl/ctl/ctr.go` — khôi phục flag CLI `--config-path` (no-op) để tương thích với
  `addons/redis` ComponentDefinitions.

## 6. Việc cần làm tiếp (không nằm trong scope task này)

- Kiểm tra xem ngoài `--config-path`, các template addon khác (mysql, postgres, mongodb, ...) có
  đang gọi `dbctl` với flag nào khác đã bị xoá ở cùng commit `9c9abec` không (ví dụ
  `--disable-dns-checker`, `--tools-dir`) để tránh lặp lại sự cố tương tự khi deploy các addon đó.

- Build multi-arch thật (amd64/arm64) và push lên registry (`quay.io/kubeblocks/apecloud/dbctl`)
  với tag mới, sau khi review.
- Định kỳ chạy lại `trivy image` trong CI để bắt CVE mới phát sinh (kể cả LOW/MEDIUM còn sót).
- Cân nhắc pin `go.mod`'s `go` directive theo support policy của team (Go 1.25 vẫn đang được
  support) trước khi merge.
