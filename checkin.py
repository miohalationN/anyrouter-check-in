#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import random
import sys
import time
from datetime import datetime

if hasattr(sys.stdout, 'reconfigure'):
	sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, 'reconfigure'):
	sys.stderr.reconfigure(line_buffering=True)

import httpx
from cloakbrowser import launch_async
from dotenv import load_dotenv

# 必须先加载 .env：utils.notify 在导入时就会读取环境变量（PUSHPLUS_TOKEN 等）
load_dotenv()

from utils.browser import (
	BrowserLoginResult,
	has_session_cookie,
	is_logged_in,
	launch_login_context,
	load_browser_login_settings,
	login_with_email_form,
	navigate_login_page,
	prepare_browser_page,
	save_login_screenshot,
	take_pending_screenshots,
	verify_browser_login,
	wait_for_waf_ready,
)
from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.debug import debug_print, is_debug_enabled
from utils.notify import notify
from utils.proxy import get_playwright_proxy, get_proxy_server

BALANCE_HASH_FILE = 'balance_hash.txt'
CHECKIN_DONE_FILE = 'checkin_done.txt'


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:  # nosec B110
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def load_checkin_done_date():
	"""加载当天已成功签到的标记日期"""
	try:
		if os.path.exists(CHECKIN_DONE_FILE):
			with open(CHECKIN_DONE_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:  # nosec B110
		pass
	return None


def save_checkin_done_date(date_str):
	"""记录当天已成功签到"""
	try:
		with open(CHECKIN_DONE_FILE, 'w', encoding='utf-8') as f:
			f.write(date_str)
	except Exception as e:
		print(f'Warning: Failed to save check-in done marker: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	simple_balances = (
		{k: {'quota': v.get('quota'), 'used': v.get('used')} for k, v in balances.items()} if balances else {}
	)
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


async def get_waf_cookies_with_browser(
	account_name: str,
	login_url: str,
	required_cookies: list[str],
	*,
	use_proxy: bool = False,
):
	"""使用浏览器获取 WAF cookies"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

	launch_kwargs: dict = {'headless': True}
	proxy = get_playwright_proxy(use_proxy=use_proxy)
	if proxy:
		launch_kwargs['proxy'] = proxy
	browser = await launch_async(**launch_kwargs)

	try:
		page = await browser.new_page()
		await prepare_browser_page(page)
		print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')

		await page.goto(login_url, wait_until='domcontentloaded')
		await wait_for_waf_ready(page)

		cookies = await page.context.cookies()

		waf_cookies = {}
		for cookie in cookies:
			cookie_name = cookie.get('name')
			cookie_value = cookie.get('value')
			if cookie_name in required_cookies and cookie_value is not None:
				waf_cookies[cookie_name] = cookie_value

		print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies')

		missing_cookies = [c for c in required_cookies if c not in waf_cookies]

		if missing_cookies:
			print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
			await browser.close()
			return None

		print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')
		await browser.close()
		return waf_cookies

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
		await browser.close()
		return None


async def login_with_credentials(
	account_name: str,
	provider_config,
	provider_name: str,
	email: str,
	password: str,
) -> BrowserLoginResult | None:
	"""使用邮箱密码通过浏览器登录，返回 cookies 与拦截到的 api user id。"""
	print(f'[PROCESSING] {account_name}: Logging in with email/password...')

	login_url = f'{provider_config.domain}{provider_config.login_path}'
	settings = load_browser_login_settings(
		account_name,
		provider_name,
		persist_profile=provider_config.persist_profile,
	)
	timeout_ms = settings.wait_timeout_ms

	debug_print(
		f'[INFO] {account_name}: Browser profile={settings.profile_dir}, '
		f'persist={settings.persist_profile}, headless={settings.headless}, '
		f'humanize={settings.humanize}, timeout={timeout_ms}ms'
	)

	print(
		f'[INFO] {account_name}: Provider proxy={"enabled" if provider_config.use_proxy else "disabled"} '
		f'({provider_name})'
	)

	try:
		context = await launch_login_context(settings, use_proxy=provider_config.use_proxy)
	except Exception as e:
		print(f'[FAILED] {account_name}: Browser launch failed: {e}')
		return None

	page = None
	try:
		page = await context.new_page()
		await prepare_browser_page(page)
		await navigate_login_page(
			page,
			login_url,
			timeout_ms,
			provider=provider_name,
			account_name=account_name,
		)

		if not await is_logged_in(page):
			if await has_session_cookie(page):
				print(f'[WARN] {account_name}: Stale session cookie on login page, forcing email login')
			await save_login_screenshot(page, provider_name, account_name, 'before-email-login')
			await login_with_email_form(
				page,
				email,
				password,
				timeout_ms,
				provider=provider_name,
				account_name=account_name,
			)
		else:
			print(f'[INFO] {account_name}: Browser profile already logged in')

		console_url = f'{provider_config.domain}/console'
		user_profile = await verify_browser_login(page, console_url, timeout_ms)
		if not user_profile:
			cookies = await context.cookies()
			cookie_names = [c.get('name') for c in cookies if c.get('name')]
			print(f'[FAILED] {account_name}: Login failed - /api/user/self not verified')
			debug_print(f'[INFO] {account_name}: Current URL: {page.url}')
			debug_print(f'[INFO] {account_name}: Got cookies: {cookie_names}')
			await save_login_screenshot(page, provider_name, account_name, 'not-authenticated')
			await context.close()
			return None

		cookies = await context.cookies()
		all_cookies = {
			cookie.get('name'): cookie.get('value') for cookie in cookies if cookie.get('name') and cookie.get('value')
		}
		api_user = str(user_profile['id']) if user_profile.get('id') is not None else None

		success_msg = f'[SUCCESS] {account_name}: Login successful, got {len(all_cookies)} cookies'
		if is_debug_enabled() and api_user:
			success_msg += f', api_user={api_user}'
		print(success_msg)
		await context.close()
		return BrowserLoginResult(cookies=all_cookies, api_user=api_user)

	except Exception as e:
		print(f'[FAILED] {account_name}: Error during login: {e}')
		if page is not None:
			await save_login_screenshot(page, provider_name, account_name, 'login-error')
		await context.close()
		return None


def api_login(client, provider_config, account_name: str, username: str, password: str) -> bool | None:
	"""通过 API 密码登录触发每日奖励。

	agentrouter 等站点的每日签到奖励在"登录成功"时发放：每天第一次登录到账，
	之后的登录接口仍会返回 checked_in=true，但不再加钱（该标志不可作为到账依据）。
	仅凭 session cookie 请求用户信息永远不会触发登录事件。

	返回 True 表示登录成功（当日首次则奖励已到账）；None 表示登录失败。
	"""
	login_url = f'{provider_config.domain}/api/user/login'
	try:
		response = client.post(
			login_url,
			json={'username': username, 'password': password},
			headers={'Referer': f'{provider_config.domain}/login', 'Origin': provider_config.domain},
			timeout=30,
		)
	except Exception as e:
		print(f'[FAILED] {account_name}: Login request error - {str(e)[:80]}')
		return None

	if response.status_code != 200:
		print(f'[FAILED] {account_name}: Login HTTP {response.status_code}')
		return None

	try:
		result = response.json()
	except Exception:
		print(f'[FAILED] {account_name}: Login returned non-JSON response')
		return None

	if not result.get('success'):
		msg = result.get('message', 'Unknown error')
		print(f'[FAILED] {account_name}: Login rejected - {msg}')
		return None

	user_data = result.get('data') or {}
	# httpx 自动用 Set-Cookie 刷新会话，后续请求使用新 session
	print(f"[SUCCESS] {account_name}: Login OK (checked_in flag={user_data.get('checked_in')}, 奖励是否到账以余额增量为准)")
	return True


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息（网络/SSL 错误会抛出异常，由上层重试处理）"""
	response = client.get(user_info_url, headers=headers, timeout=30)

	if response.status_code == 200:
		try:
			data = response.json()
		except Exception:
			content_type = response.headers.get('content-type', 'unknown')
			snippet = response.text[:150].replace('\n', ' ').replace('\r', ' ')
			print(f'[DEBUG] User info HTTP 200 but non-JSON (content-type: {content_type}): {snippet}')
			raise RuntimeError(f'user info returned non-JSON (HTTP 200, {content_type})')
		if data.get('success'):
			user_data = data.get('data', {})
			quota = round(user_data.get('quota', 0) / 500000, 2)
			used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
			return {
				'success': True,
				'quota': quota,
				'used_quota': used_quota,
				'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
			}
	return {'success': False, 'error': f'Failed to get user info: HTTP {response.status_code}'}


def _request_with_retry(func, *args, attempts: int = 3, base_delay: float = 2.0, **kwargs):
	"""对可能因网络抖动失败的请求做重试（如 SSL 连接被对端中断）。"""
	last_exc = None
	for attempt in range(1, attempts + 1):
		try:
			return func(*args, **kwargs)
		except Exception as exc:
			last_exc = exc
			if attempt < attempts:
				print(f'[RETRY] Request attempt {attempt}/{attempts} failed ({str(exc)[:50]}...), retrying...')
				time.sleep(base_delay * attempt)
	raise last_exc


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_browser(
			account_name,
			login_url,
			provider_config.waf_cookie_names,
			use_proxy=provider_config.use_proxy,
		)
		if not waf_cookies:
			print(f'[FAILED] {account_name}: Unable to get WAF cookies')
			return None
	else:
		print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')

	return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'[NETWORK] {account_name}: Executing check-in')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				error_msg = result.get('msg', result.get('message', 'Unknown error'))
				already_checked_keywords = ['已经签到', '已签到', '重复签到', 'already checked', 'already signed']
				if any(keyword in error_msg.lower() for keyword in already_checked_keywords):
					print(f'[SUCCESS] {account_name}: Already checked in today')
					return True
				print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
				return False
		except json.JSONDecodeError:
			if 'success' in response.text.lower():
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
				return False
	else:
		print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
		return False


def format_check_in_notification(detail: dict) -> str:
	"""格式化签到通知消息（HTML，供推送渲染）"""
	sep = '──────────────────'
	name = detail['name']
	status = f"<b>{'✅' if detail['success'] else '❌'} {name}</b><br>"
	has_reward = detail['check_in_reward'] != 0
	has_usage = detail['usage_increase'] != 0
	balance_change = detail['balance_change']

	lines = [
		status,
		f'签到前余额: <b>${detail["before_quota"]:.2f}</b> ｜ 累计消耗: ${detail["before_used"]:.2f}<br>',
		f'签到后余额: <b>${detail["after_quota"]:.2f}</b> ｜ 累计消耗: ${detail["after_used"]:.2f}<br>',
	]

	if has_reward or has_usage or balance_change != 0:
		lines.append(f'{sep}<br>')
		if has_reward:
			lines.append(f'签到获得: <font color="#4caf50"><b>+${detail["check_in_reward"]:.2f}</b></font> 🎁<br>')
		if has_usage:
			lines.append(f'期间消耗: <font color="#e53935">${detail["usage_increase"]:.2f}</font><br>')
		if balance_change != 0:
			change_symbol = '+' if balance_change > 0 else ''
			color = '#4caf50' if balance_change > 0 else '#e53935'
			lines.append(f'余额变化: <font color="{color}"><b>{change_symbol}${balance_change:.2f}</b></font><br>')
	else:
		lines.append('今日已签到，无变化<br>')

	return ''.join(lines)


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
		return False, None, None

	print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

	# 邮箱密码优先
	all_cookies = None
	resolved_api_user: str | None = None
	auth_method = None
	if account.has_login_credentials():
		print(f'[INFO] {account_name}: Attempting email/password login (priority)...')
		assert account.email is not None and account.password is not None
		login_result = await login_with_credentials(
			account_name,
			provider_config,
			account.provider,
			account.email,
			account.password,
		)
		if login_result:
			all_cookies = login_result.cookies
			resolved_api_user = login_result.api_user
			auth_method = 'email/password'
		else:
			print(f'[FAILED] {account_name}: Email/password login failed, will not use stale session cookies')
			return False, None, None
	else:
		user_cookies = parse_cookies(account.cookies)
		if not user_cookies:
			print(f'[FAILED] {account_name}: Invalid configuration format')
			return False, None, None
		all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
		auth_method = 'session cookies'

	if not all_cookies:
		return False, None, None

	print(f'[AUTH] {account_name}: Using auth method -> {auth_method}')

	return run_check_in_requests(
		all_cookies,
		account,
		account_name,
		provider_config,
		api_user_override=resolved_api_user,
		use_proxy=provider_config.use_proxy,
	)


def run_check_in_requests(
	all_cookies: dict,
	account: AccountConfig,
	account_name: str,
	provider_config,
	*,
	api_user_override: str | None = None,
	use_proxy: bool = False,
) -> tuple[bool, dict | None, dict | None]:
	"""执行 HTTP 签到请求（同步，避免在 async 上下文中使用阻塞 httpx）。"""
	try:
		client_kwargs: dict = {'http2': False, 'timeout': 30.0}
		proxy_url = get_proxy_server(use_proxy=use_proxy)
		if proxy_url:
			client_kwargs['proxy'] = proxy_url
			if is_debug_enabled():
				print(f'[INFO] {account_name}: HTTP client proxy enabled: {proxy_url}')
			else:
				print(f'[INFO] {account_name}: HTTP client proxy enabled')
		elif use_proxy:
			print(f'[WARN] {account_name}: Provider requires proxy but CHECKIN_PROXY_URL is not set')

		with httpx.Client(**client_kwargs) as client:
			client.cookies.update(all_cookies)

			headers = {
				'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				'Accept': 'application/json, text/plain, */*',
				'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
				'Accept-Encoding': 'gzip, deflate, br, zstd',
				'Referer': provider_config.domain,
				'Origin': provider_config.domain,
				'Connection': 'keep-alive',
				'Sec-Fetch-Dest': 'empty',
				'Sec-Fetch-Mode': 'cors',
				'Sec-Fetch-Site': 'same-origin',
			}

			api_user = api_user_override or account.api_user
			if api_user:
				headers[provider_config.api_user_key] = api_user

			user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
			user_info_before = _request_with_retry(get_user_info, client, headers, user_info_url)
			if user_info_before and user_info_before.get('success'):
				print(user_info_before['display'])
			elif user_info_before:
				print(user_info_before.get('error', 'Unknown error'))

			if provider_config.needs_manual_check_in():
				success = _request_with_retry(execute_check_in, client, account_name, provider_config, headers)
				user_info_after = _request_with_retry(get_user_info, client, headers, user_info_url)
				return success, user_info_before, user_info_after

			# 自动奖励型 provider（如 agentrouter）：每天第一次登录发放奖励
			if account.has_api_login_credentials():
				login_status = _request_with_retry(
					api_login,
					client,
					provider_config,
					account_name,
					account.get_login_username(),
					account.password,
				)
				user_info_after = _request_with_retry(get_user_info, client, headers, user_info_url)
				if login_status is None:
					error = user_info_after.get('error', 'login failed') if user_info_after else 'login failed'
					print(f'[FAILED] {account_name}: Login-based check-in failed - {error}')
					return False, user_info_before, user_info_after
				# 登录成功即视为今日签到完成；是否到账看通知里的余额增量
				# （当天已在别处登录过时增量为 0，属正常）
				return True, user_info_before, user_info_after

			# 未配置密码：无法触发登录，只能凭余额增量判断奖励是否真的到账
			print(
				f'[WARN] {account_name}: No login password configured - '
				f'this provider grants daily credit only at LOGIN; reward will NOT be credited without it'
			)
			user_info_after = _request_with_retry(get_user_info, client, headers, user_info_url)
			if user_info_after and user_info_after.get('success'):
				if (
					user_info_before
					and user_info_before.get('success')
					and (user_info_after['quota'] + user_info_after['used_quota'])
					- (user_info_before['quota'] + user_info_before['used_quota'])
					> 0
				):
					print(f'[SUCCESS] {account_name}: Balance grew during check-in (reward credited elsewhere)')
					return True, user_info_before, user_info_after
				print(f'[FAILED] {account_name}: No reward credited - configure "password" for this account')
				return False, user_info_before, user_info_after
			error = user_info_after.get('error', 'Unknown error') if user_info_after else 'Unknown error'
			print(f'[FAILED] {account_name}: Auto check-in failed - {error}')
			return False, user_info_before, user_info_after

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...')
		return False, None, None


async def main():
	"""主函数"""
	if is_debug_enabled():
		print('[INFO] DEBUG_MODE enabled')
		proxy_server = os.getenv('CHECKIN_PROXY_URL', '').strip()
		if proxy_server:
			print(f'[INFO] Proxy endpoint available: {proxy_server} (enabled per provider use_proxy)')
		else:
			print('[INFO] CHECKIN_PROXY_URL not set; providers with use_proxy=true will run without proxy')
	else:
		print('[INFO] Debug mode disabled (set DEBUG_MODE=true to enable screenshots and verbose logs)')

	print('[SYSTEM] AnyRouter.top multi-account auto check-in script started')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	app_config = AppConfig.load_from_env()
	print(f'[INFO] Loaded {len(app_config.providers)} provider configuration(s)')
	if is_debug_enabled():
		for provider_name, provider in sorted(app_config.providers.items()):
			print(f'[INFO] Provider "{provider_name}": use_proxy={provider.use_proxy}')

	accounts = load_accounts_config()
	if not accounts:
		error_msg = '[FAILED] Unable to load account configuration, program exits'
		print(error_msg)
		notify.push_message('AnyRouter Check-in Alert', error_msg, msg_type='text')
		sys.exit(1)

	print(f'[INFO] Found {len(accounts)} account configurations')

	today_str = datetime.now().strftime('%Y-%m-%d')
	if load_checkin_done_date() == today_str:
		print(f'[INFO] Today ({today_str}) check-in already completed successfully, skipping this run')
		sys.exit(0)

	last_balance_hash = load_balance_hash()

	success_count = 0
	total_count = len(accounts)
	account_notify_blocks = {}
	current_balances = {}
	account_check_in_details = {}
	need_notify = False
	balance_changed = False

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		if i > 0:
			delay = random.uniform(30, 120)
			print(f'[INFO] Waiting {delay:.0f}s before next account (desync anti-detection)...')
			await asyncio.sleep(delay)
		try:
			success, user_info_before, user_info_after = await check_in_account(account, i, app_config)
			if success:
				success_count += 1

			should_notify_this_account = True
			need_notify = True

			if not success:
				account_name = account.get_display_name(i)
				print(f'[NOTIFY] {account_name} failed, will send notification')

			if user_info_after and user_info_after.get('success'):
				current_quota = user_info_after['quota']
				current_used = user_info_after['used_quota']
				current_balances[account_key] = {'quota': current_quota, 'used': current_used}

				if user_info_before and user_info_before.get('success'):
					before_quota = user_info_before['quota']
					before_used = user_info_before['used_quota']
					after_quota = user_info_after['quota']
					after_used = user_info_after['used_quota']

					total_before = before_quota + before_used
					total_after = after_quota + after_used

					check_in_reward = total_after - total_before
					usage_increase = after_used - before_used
					balance_change = after_quota - before_quota

					account_check_in_details[account_key] = {
						'name': account.get_display_name(i),
						'before_quota': before_quota,
						'before_used': before_used,
						'after_quota': after_quota,
						'after_used': after_used,
						'check_in_reward': check_in_reward,
						'usage_increase': usage_increase,
						'balance_change': balance_change,
						'success': success,
					}

			if should_notify_this_account:
				account_name = account.get_display_name(i)
				icon = '✅' if success else '❌'
				if user_info_after and user_info_after.get('success'):
					account_result = (
						f'<b>{icon} {account_name}</b><br>'
						f'余额: <b>${user_info_after["quota"]:.2f}</b> ｜ 累计消耗: ${user_info_after["used_quota"]:.2f}'
					)
				elif user_info_after:
					err = user_info_after.get('error', 'Unknown error')
					account_result = f'<b>{icon} {account_name}</b><br>{err}'
				else:
					account_result = f'<b>{icon} {account_name}</b>'
				account_notify_blocks[account_key] = account_result

		except Exception as e:
			account_name = account.get_display_name(i)
			print(f'[FAILED] {account_name} processing exception: {e}')
			need_notify = True
			account_notify_blocks[account_key] = f'<b>❌ {account_name}</b><br>异常: {str(e)[:50]}...'

	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			balance_changed = True
			need_notify = True
			print('[NOTIFY] First run detected, will send notification with current balances')
		elif current_balance_hash != last_balance_hash:
			balance_changed = True
			need_notify = True
			print('[NOTIFY] Balance changes detected, will send notification')
		else:
			print('[INFO] No balance changes detected')

	if balance_changed:
		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in account_check_in_details:
				account_notify_blocks[account_key] = format_check_in_notification(account_check_in_details[account_key])

	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if total_count > 0 and success_count == total_count:
		save_checkin_done_date(today_str)
		print(f'[INFO] All accounts check-in successful, marked as done for today ({today_str})')

	if need_notify and account_notify_blocks:
		time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		blocks = [
			account_notify_blocks[f'account_{i + 1}']
			for i in range(total_count)
			if f'account_{i + 1}' in account_notify_blocks
		]
		if success_count == total_count:
			stats_html = f'✅ <b>全部成功 {success_count}/{total_count}</b>'
		elif success_count > 0:
			stats_html = f'⚠️ <b>部分成功 {success_count}/{total_count}（失败 {total_count - success_count}）</b>'
		else:
			stats_html = f'❌ <b>全部失败 0/{total_count}</b>'
		notify_content = (
			'💰 <b>AnyRouter 签到结果</b><br>'
			f'<i>{time_str}</i><br><br>'
			+ '<br><br>━━━━━━━━━━━<br><br>'.join(blocks)
			+ f'<br><br>📊 <b>{stats_html}</b>'
		)
		screenshot_paths = take_pending_screenshots() if is_debug_enabled() else []
		if screenshot_paths:
			github_run_id = os.getenv('GITHUB_RUN_ID', '').strip()
			github_repo = os.getenv('GITHUB_REPOSITORY', '').strip()
			screenshot_hint = f'📷 {len(screenshot_paths)} 张调试截图'
			if github_run_id and github_repo:
				run_url = f'https://github.com/{github_repo}/actions/runs/{github_run_id}'
				screenshot_hint += f'（<a href=\"{run_url}\">查看</a>）'
			notify_content += f'<br><br>{screenshot_hint}'
		print(notify_content)
		notify.push_message('💰 AnyRouter 签到结果', notify_content, msg_type='html')
		print('[NOTIFY] Check-in result notification sent')
	else:
		print('[INFO] All accounts successful and no balance changes detected, notification skipped')

	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
