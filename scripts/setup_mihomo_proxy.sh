#!/usr/bin/env bash
# 通过 mihomo 拉取订阅、启动本地代理并探测可用节点。
# 环境变量:
#   PROXY_SUBSCRIPTION_URL  订阅链接（必填才启用）
#   PROXY_TEST_URL          探测目标，默认 https://www.google.com/generate_204
#   PROXY_REQUIRED          true 时探测失败则退出 1
#   PROXY_PORT              本地 mixed-port，默认 7890

set -euo pipefail

if [[ -z "${PROXY_SUBSCRIPTION_URL:-}" ]]; then
	echo "[INFO] PROXY_SUBSCRIPTION_URL not set, skip proxy setup"
	exit 0
fi

PROXY_DIR="${RUNNER_TEMP:-/tmp}/checkin-proxy"
PROXY_PORT="${PROXY_PORT:-7890}"
PROXY_TEST_URL="${PROXY_TEST_URL:-https://www.google.com/generate_204}"
MIHOMO_VERSION="${MIHOMO_VERSION:-v1.19.0}"
PROXY_REQUIRED="${PROXY_REQUIRED:-false}"

mkdir -p "${PROXY_DIR}"
cd "${PROXY_DIR}"

MIHOMO_BIN="${PROXY_DIR}/mihomo-linux-amd64-${MIHOMO_VERSION}"
if [[ ! -x "${MIHOMO_BIN}" ]]; then
	echo "[INFO] Downloading mihomo ${MIHOMO_VERSION}..."
	ARCHIVE="mihomo-linux-amd64-${MIHOMO_VERSION}.gz"
	MIHOMO_URL="https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${ARCHIVE}"
	if ! curl --retry 3 --retry-delay 5 --retry-all-errors -fsSL -o "${ARCHIVE}" "${MIHOMO_URL}"; then
		echo "[INFO] Primary download failed, trying mirror..."
		if ! curl --retry 2 --retry-delay 5 -fsSL -o "${ARCHIVE}" "https://ghfast.top/${MIHOMO_URL}"; then
			echo "[WARN] Failed to download mihomo ${MIHOMO_VERSION}, skip proxy setup"
			if [[ "${PROXY_REQUIRED}" == "true" ]]; then
				exit 1
			fi
			exit 0
		fi
	fi
	gunzip -f "${ARCHIVE}"
	chmod +x "mihomo-linux-amd64-${MIHOMO_VERSION}"
else
	echo "[INFO] mihomo ${MIHOMO_VERSION} already present, skipping download"
fi

echo "[INFO] Downloading subscription..."
if ! curl --retry 3 --retry-delay 5 --retry-all-errors -fsSL -o "${PROXY_DIR}/subscription_raw.yaml" "${PROXY_SUBSCRIPTION_URL}"; then
	echo "[WARN] Failed to download subscription, skip proxy setup"
	if [[ "${PROXY_REQUIRED}" == "true" ]]; then
		exit 1
	fi
	exit 0
fi

# 过滤订阅：默认仅保留日本节点，排除免费/下载专用等无法通过目标站点 WAF 的节点；
# 若订阅中无日本节点则回退到全部节点。纯标准库实现，无需额外依赖。
if ! python3 - "${PROXY_DIR}/subscription_raw.yaml" "${PROXY_DIR}/subscription.yaml" <<'PY'
import re
import sys

src, dst = sys.argv[1], sys.argv[2]
lines = open(src, encoding='utf-8').read().splitlines()

proxies_idx = next((i for i, line in enumerate(lines) if line.strip() == 'proxies:'), None)
if proxies_idx is None:
    print('[WARN] proxies section not found in subscription')
    sys.exit(1)

section_end = len(lines)
for i in range(proxies_idx + 1, len(lines)):
    if re.match(r'^[a-zA-Z_][\w-]*:', lines[i]):
        section_end = i
        break

body = lines[proxies_idx + 1:section_end]
exclude = ('免费', '下载专用')


def extract_name(line):
    m = re.match(r'^\s*-\s*\{name:\s*(?:"([^"]*)"|([^,}]+))', line)
    return (m.group(1) or m.group(2)).strip() if m else ''


kept = []
total = 0
i = 0
while i < len(body):
    line = body[i]
    if re.match(r'^\s*-\s*\{name:', line):
        total += 1
        name = extract_name(line)
        if '日本' in name and not any(k in name for k in exclude):
            kept.append(line)
        i += 1
    elif re.match(r'^\s*-\s*name:', line):
        block = [line]
        i += 1
        while i < len(body) and body[i] and not re.match(r'^\s*-\s', body[i]):
            block.append(body[i])
            i += 1
        total += 1
        m = re.search(r'name:\s*["\']?([^"\']+)', block[0])
        name = m.group(1).strip() if m else ''
        if '日本' in name and not any(k in name for k in exclude):
            kept.extend(block)
    else:
        kept.append(line)
        i += 1

selected = kept if kept else body
with open(dst, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines[:proxies_idx + 1] + selected + lines[section_end:]) + '\n')
print(f'[INFO] Proxy nodes: kept {len(selected)}/{len(body)} (Japan: {sum(1 for l in selected if "日本" in extract_name(l))})')
PY
then
	echo "[WARN] Failed to filter subscription, skip proxy setup"
	if [[ "${PROXY_REQUIRED}" == "true" ]]; then
		exit 1
	fi
	exit 0
fi

cat > config.yaml <<EOF
mixed-port: ${PROXY_PORT}
allow-lan: false
ipv6: false
mode: rule
log-level: warning
unified-delay: true

proxy-providers:
  subscription:
    type: file
    path: ${PROXY_DIR}/subscription.yaml
    health-check:
      enable: true
      interval: 300
      url: https://www.gstatic.com/generate_204

proxy-groups:
  - name: CHECKIN
    type: url-test
    url: "${PROXY_TEST_URL}"
    interval: 300
    tolerance: 150
    lazy: false
    use:
      - subscription

rules:
  - MATCH,CHECKIN
EOF

echo "[INFO] Starting mihomo on 127.0.0.1:${PROXY_PORT}..."
nohup "${MIHOMO_BIN}" -d "${PROXY_DIR}" -f config.yaml > mihomo.log 2>&1 &
echo $! > mihomo.pid

PROXY_URL="http://127.0.0.1:${PROXY_PORT}"
READY=false
for attempt in $(seq 1 45); do
	if curl -fsS -x "${PROXY_URL}" --max-time 20 "${PROXY_TEST_URL}" -o /dev/null 2>/dev/null; then
		READY=true
		break
	fi
	echo "[INFO] Waiting for proxy health check (${attempt}/45)..."
	sleep 2
done

if [[ "${READY}" != "true" ]]; then
	echo "[FAILED] Proxy health check failed for ${PROXY_TEST_URL}"
	tail -n 30 mihomo.log || true
	if [[ -f mihomo.pid ]]; then
		kill "$(cat mihomo.pid)" 2>/dev/null || true
	fi
	if [[ "${PROXY_REQUIRED}" == "true" ]]; then
		exit 1
	fi
	exit 0
fi

echo "[SUCCESS] Proxy is ready: ${PROXY_URL}"
echo "[INFO] Proxy is scoped to CHECKIN_PROXY_URL (browser/python only, not global HTTP_PROXY)"
if [[ -n "${GITHUB_ENV:-}" ]]; then
	echo "CHECKIN_PROXY_URL=${PROXY_URL}" >> "${GITHUB_ENV}"
fi
