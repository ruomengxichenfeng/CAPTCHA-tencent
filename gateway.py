# -*- coding: utf-8 -*-
"""
腾讯云验证码（天御）防爬网关 —— Python 3 版（仅标准库，零第三方依赖）

职责：
  1. GET  /_auth        被 nginx auth_request 调用，核验免验证 Cookie（HMAC 签名 + 过期时间）
  2. POST /verify       接收前端 ticket + randstr，调用腾讯 DescribeCaptchaResult 二次校验，通过后下发签名 Cookie
  3. GET  /captcha.html 输出验证码页面（自动替换 __CAPTCHA_APP_ID__ 占位符）

监听 127.0.0.1，仅由本机 nginx 反代访问，切勿直接暴露公网。
兼容 Python 3.6+（CentOS 7 yum 安装的 python3 即可）。
"""

import os
import sys
import json
import time
import hmac
import hashlib
import re
import http.client
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

CONFIG = {
    'CAPTCHA_APP_ID': os.environ.get('CAPTCHA_APP_ID', '199'),  # 验证码 CaptchaAppId
    'APP_SECRET_KEY': os.environ.get('APP_SECRET_KEY', ''),           # 验证码 AppSecretKey（必填）
    'TENCENT_SECRET_ID': os.environ.get('TENCENT_SECRET_ID', ''),     # 云 API 密钥 SecretId（必填）
    'TENCENT_SECRET_KEY': os.environ.get('TENCENT_SECRET_KEY', ''),   # 云 API 密钥 SecretKey（必填）
    'COOKIE_SECRET': os.environ.get('COOKIE_SECRET', ''),             # 自定 Cookie 签名密钥（必填，随机长字符串）
    'PORT': int(os.environ.get('PORT', '8000')),
    'SESSION_TTL_SEC': int(os.environ.get('SESSION_TTL_SEC', str(24 * 3600))),  # 通过后免验证时长（秒），默认 1 天
    'COOKIE_NAME': os.environ.get('COOKIE_NAME', '__trae_captcha'),
    'FP_COOKIE_NAME': os.environ.get('FP_COOKIE_NAME', '__trae_captcha_fp'),  # 浏览器指纹 Cookie 名
    'COOKIE_SECURE': os.environ.get('COOKIE_SECURE', '0') == '1',     # HTTPS 站点请设为 1
    'ALLOW_DR_TICKET': os.environ.get('ALLOW_DR_TICKET', '0') == '1',  # 是否放行 trerror 容灾票据（防爬建议保持 0）
    'VERIFY_RATE_LIMIT_MIN': int(os.environ.get('VERIFY_RATE_LIMIT_MIN', '20')),  # 每 IP 每分钟 /verify 调用上限
    'VERIFY_DAILY_LIMIT': int(os.environ.get('VERIFY_DAILY_LIMIT', '100')),        # 每 IP 每日签发 Cookie 上限
}

CAPTCHA_HTML = ''
CAPTCHA_HTML_MTIME = 0.0


def load_captcha_html(force=False):
    """按 mtime 热加载 captcha.html：文件变更后下一个请求即生效，无需重启进程。"""
    global CAPTCHA_HTML, CAPTCHA_HTML_MTIME
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'captcha.html')
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return
    if force or mtime != CAPTCHA_HTML_MTIME:
        with open(path, 'r', encoding='utf-8') as f:
            CAPTCHA_HTML = f.read().replace('__CAPTCHA_APP_ID__', CONFIG['CAPTCHA_APP_ID'])
        CAPTCHA_HTML_MTIME = mtime


# ---------------- 基础工具 ----------------
def _hmac_bin(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def _hmac_hex(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).hexdigest()


def sha256_hex(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def client_ip(handler):
    xri = handler.headers.get('X-Real-IP') or ''
    xff = handler.headers.get('X-Forwarded-For') or ''
    raw = (xri.split(',')[0].strip() or xff.split(',')[0].strip()
           or handler.client_address[0] or '')
    if raw.startswith('::ffff:'):
        raw = raw[7:]
    return raw


def read_cookie_named(handler, name):
    header = handler.headers.get('Cookie') or ''
    for part in header.split(';'):
        if '=' in part:
            k, _, v = part.partition('=')
            if k.strip() == name:
                return v.strip()
    return None


def read_cookie(handler):
    return read_cookie_named(handler, CONFIG['COOKIE_NAME'])


def read_fp_cookie(handler):
    return read_cookie_named(handler, CONFIG['FP_COOKIE_NAME'])


def _bind_hash(kind, value):
    # 将 kind+value 散列进 token，用于会话与来源绑定（不直接存明文）
    return _hmac_hex(CONFIG['COOKIE_SECRET'].encode('utf-8'), '%s:%s' % (kind, value))


def sign_token(ttl_sec, ip, fp):
    """签发绑定来源 IP 与浏览器指纹的会话 token。格式: exp.ip_hash.fp_hash.sig"""
    exp = int(time.time()) + ttl_sec
    ip_h = _bind_hash('ip', ip)
    fp_h = _bind_hash('fp', fp)
    payload = '%d.%s.%s' % (exp, ip_h, fp_h)
    return '%s.%s' % (payload, _hmac_hex(CONFIG['COOKIE_SECRET'].encode('utf-8'), payload))


def verify_token(token, ip, fp):
    """校验 token 的签名与其来源 IP / 浏览器指纹是否一致。"""
    if not token:
        return False
    parts = token.split('.')
    if len(parts) != 4:
        return False
    exp_s, ip_h, fp_h, sig = parts
    if not exp_s.isdigit():
        return False
    if not hmac.compare_digest(ip_h, _bind_hash('ip', ip)):
        return False
    if not hmac.compare_digest(fp_h, _bind_hash('fp', fp)):
        return False
    payload = '%s.%s.%s' % (exp_s, ip_h, fp_h)
    expected = _hmac_hex(CONFIG['COOKIE_SECRET'].encode('utf-8'), payload)
    return hmac.compare_digest(sig, expected) and int(exp_s) > int(time.time())


# ---------------- /verify 每 IP 限流（内存版，进程重启即清零） ----------------
# 多线程服务，共享 _RATE_STATE 需要加锁保护。
_RATE_STATE = {}      # ip -> {'min': [ts,...], 'day': 'YYYY-MM-DD', 'day_count': int}
_RATE_LOCK = threading.Lock()


def _rate_state(ip):
    st = _RATE_STATE.get(ip)
    if st is None:
        st = {'min': [], 'day': time.strftime('%Y-%m-%d', time.localtime()), 'day_count': 0}
        _RATE_STATE[ip] = st
    return st


def check_verify_rate(ip):
    """分钟级滑动窗口：超过每分钟上限则拒绝（在调用腾讯 API 前执行）。"""
    with _RATE_LOCK:
        now = time.time()
        st = _rate_state(ip)
        st['min'] = [t for t in st['min'] if now - t < 60]
        if len(st['min']) >= CONFIG['VERIFY_RATE_LIMIT_MIN']:
            return False
        st['min'].append(now)
        return True


def check_verify_daily(ip):
    """每日签发额度检查：超过每日上限则拒绝（在调用腾讯 API 前执行）。"""
    with _RATE_LOCK:
        st = _rate_state(ip)
        today = time.strftime('%Y-%m-%d', time.localtime())
        if st['day'] != today:
            st['day'] = today
            st['day_count'] = 0
        return st['day_count'] < CONFIG['VERIFY_DAILY_LIMIT']


def record_verify_success(ip):
    """验证通过并签发 Cookie 后，每日计数 +1。"""
    with _RATE_LOCK:
        _rate_state(ip)['day_count'] += 1


# ---------------- 调用腾讯云 API 3.0：DescribeCaptchaResult ----------------
def describe_captcha_result(ticket, randstr, user_ip):
    host = 'captcha.tencentcloudapi.com'
    service = 'captcha'
    action = 'DescribeCaptchaResult'
    version = '2019-07-22'

    payload = json.dumps({
        'CaptchaType': 9,
        'CaptchaAppId': int(CONFIG['CAPTCHA_APP_ID']),
        'AppSecretKey': CONFIG['APP_SECRET_KEY'],
        'Ticket': ticket,
        'Randstr': randstr,
        'UserIp': user_ip,
    })

    timestamp = int(time.time())
    date = time.strftime('%Y-%m-%d', time.gmtime(timestamp))

    canonical_headers = 'content-type:application/json; charset=utf-8\nhost:%s\n' % host
    signed_headers = 'content-type;host'
    hashed_payload = sha256_hex(payload)
    canonical_request = 'POST\n/\n\n%s\n%s\n%s' % (canonical_headers, signed_headers, hashed_payload)

    credential_scope = '%s/%s/tc3_request' % (date, service)
    string_to_sign = 'TC3-HMAC-SHA256\n%d\n%s\n%s' % (
        timestamp, credential_scope, sha256_hex(canonical_request))

    secret_date = _hmac_bin(('TC3' + CONFIG['TENCENT_SECRET_KEY']).encode('utf-8'), date)
    secret_service = _hmac_bin(secret_date, service)
    secret_signing = _hmac_bin(secret_service, 'tc3_request')
    signature = hmac.new(secret_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    authorization = 'TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s' % (
        CONFIG['TENCENT_SECRET_ID'], credential_scope, signed_headers, signature)

    headers = {
        'Authorization': authorization,
        'Content-Type': 'application/json; charset=utf-8',
        'X-TC-Action': action,
        'X-TC-Version': version,
        'X-TC-Timestamp': str(timestamp),
    }

    try:
        conn = http.client.HTTPSConnection(host, 443, timeout=10)
        conn.request('POST', '/', body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode('utf-8')
        conn.close()
        j = json.loads(data)
        body = j.get('Response') or {}
        if body.get('Error'):
            err = body['Error']
            return {'code': None, 'msg': 'APIError: %s - %s' % (err.get('Code'), err.get('Message'))}
        return {'code': body.get('CaptchaCode'), 'msg': body.get('CaptchaMsg'),
                'evil': body.get('EvilLevel')}
    except Exception as e:  # 网络/证书/解析异常
        return {'code': None, 'msg': str(e)}


# ---------------- HTTP 服务 ----------------
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # 关闭默认访问日志，避免每请求一条刷屏
        return

    def send_json(self, status, obj, extra_headers=None):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/captcha.html':
            load_captcha_html()
            body = CAPTCHA_HTML.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == '/_auth':
            if verify_token(read_cookie(self), client_ip(self), read_fp_cookie(self) or ''):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(b'OK')
            else:
                self.send_response(401)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(b'Unauthorized')
            return
        self.send_json(404, {'ok': False, 'error': 'not found'})

    def do_POST(self):
        path = urlparse(self.path).path
        if path != '/verify':
            self.send_json(404, {'ok': False, 'error': 'not found'})
            return

        length = 0
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b''

        try:
            j = json.loads(raw.decode('utf-8') or '{}')
            ticket = j.get('ticket')
            randstr = j.get('randstr')
            fp = j.get('fp') or ''
        except Exception:
            self.send_json(400, {'ok': False, 'error': 'bad json'})
            return

        if not ticket or not randstr:
            self.send_json(400, {'ok': False, 'error': 'missing ticket/randstr'})
            return

        # 浏览器指纹：仅接受 8~128 位十六进制，保证 Cookie 安全且不可注入
        if not re.fullmatch(r'[0-9a-fA-F]{8,128}', fp):
            self.send_json(400, {'ok': False, 'error': 'invalid or missing fp'})
            return

        user_ip = client_ip(self)

        # 防刷：先过分钟级与每日额度，任何超限都拒绝（且在调用腾讯 API 之前）
        if not check_verify_rate(user_ip) or not check_verify_daily(user_ip):
            self.send_json(429, {'ok': False, 'error': 'too many requests, try later'})
            return

        # 容灾票据（前端 JS 加载失败自动生成）默认拒绝，避免被绕过
        if str(ticket).startswith('trerror_') and not CONFIG['ALLOW_DR_TICKET']:
            self.send_json(200, {'ok': False, 'error': 'disaster ticket rejected'})
            return

        r = describe_captcha_result(ticket, randstr, user_ip)
        if r['code'] == 1:
            record_verify_success(user_ip)
            token = sign_token(CONFIG['SESSION_TTL_SEC'], user_ip, fp)
            secure = '; Secure' if CONFIG['COOKIE_SECURE'] else ''
            cookie = '%s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d%s' % (
                CONFIG['COOKIE_NAME'], token, CONFIG['SESSION_TTL_SEC'], secure)
            fp_cookie = '%s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d%s' % (
                CONFIG['FP_COOKIE_NAME'], fp, CONFIG['SESSION_TTL_SEC'], secure)
            self.send_json(200, {'ok': True}, extra_headers=[
                ('Set-Cookie', cookie), ('Set-Cookie', fp_cookie)])
            return
        self.send_json(200, {'ok': False, 'error': r['msg'] or ('code=%s' % r['code'])})


def main():
    needed = ['APP_SECRET_KEY', 'TENCENT_SECRET_ID', 'TENCENT_SECRET_KEY', 'COOKIE_SECRET']
    missing = [k for k in needed if not CONFIG[k]]
    if missing:
        sys.stderr.write('[captcha-gateway] missing env: %s\n' % ', '.join(missing))
        sys.stderr.write('[captcha-gateway] 请设置：APP_SECRET_KEY、TENCENT_SECRET_ID、TENCENT_SECRET_KEY、COOKIE_SECRET\n')
        sys.exit(1)

    load_captcha_html(force=True)

    server = ThreadingHTTPServer(('127.0.0.1', CONFIG['PORT']), Handler)
    sys.stderr.write('[captcha-gateway] listening on 127.0.0.1:%d\n' % CONFIG['PORT'])
    server.serve_forever()


if __name__ == '__main__':
    main()
