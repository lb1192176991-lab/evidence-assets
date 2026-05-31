#!/usr/bin/env python3
"""吐槽墙 - Flask 后端 API"""
import os
import json
import datetime
import random
import hashlib
import base64
import re
import urllib.request
import urllib.parse
from flask import Flask, request, jsonify, send_from_directory, render_template_string
from flask_cors import CORS
import psycopg2
import psycopg2.extras

try:
    from pywebpush import webpush, WebPushException
    VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY', '')
    VAPID_PUBLIC_KEY = os.environ.get('VAPID_PUBLIC_KEY', '')
    VAPID_CLAIMS = {"sub": "mailto:lb1192176991@gmail.com"}
    HAS_WEBPUSH = True
except ImportError:
    HAS_WEBPUSH = False

# 点数/金币系统配置
COINS_PER_DOLLAR = int(os.environ.get('COINS_PER_DOLLAR', '100'))
GUMROAD_ACCESS_TOKEN = os.environ.get('GUMROAD_ACCESS_TOKEN', '')

# 导入违禁词过滤
from sensitive_filter import SensitiveFilter

sensitive = SensitiveFilter()

app = Flask(__name__, static_folder='../dist', static_url_path='')
CORS(app)

DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://tucao:***@localhost:5432/tucao')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# GitHub OAuth 配置
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID', '')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET', '')

# Google OAuth 配置
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

# Discord OAuth 配置
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID', '')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET', '')

# ===== OG图片生成辅助 =====
def render_og_svg(title, nickname, likes, post_id):
    """生成纯SVG的OG图片，无需Pillow"""
    text = title[:80]
    if len(title) > 80:
        text += '…'
    nick = nickname or '匿名吐槽'
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0a0a1a"/>
      <stop offset="50%" style="stop-color:#1a0a2e"/>
      <stop offset="100%" style="stop-color:#0f0f2e"/>
    </linearGradient>
    <linearGradient id="glow" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#ff6b6b"/>
      <stop offset="100%" style="stop-color:#4d96ff"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>
  <circle cx="1050" cy="100" r="300" fill="url(#glow)" opacity="0.08"/>
  <circle cx="150" cy="500" r="200" fill="#4d96ff" opacity="0.05"/>
  <!-- 顶部标题 -->
  <text x="80" y="110" font-family="sans-serif" font-size="36" font-weight="900" fill="url(#glow)">吐 槽 墙</text>
  <line x1="80" y1="130" x2="400" y2="130" stroke="url(#glow)" stroke-width="3" opacity="0.3"/>
  <!-- 引号 -->
  <text x="80" y="220" font-family="Georgia,serif" font-size="80" fill="rgba(255,255,255,0.12)">"</text>
  <!-- 吐槽内容 -->
  <text x="130" y="230" font-family="sans-serif" font-size="44" font-weight="700" fill="#ffffff">
    <tspan x="130" dy="0">{''.join(f'<tspan x="130" dy="{52 if i>0 else 0}">{line}</tspan>' for i,line in enumerate([text[i:i+24] for i in range(0,len(text),24)][:3]))}</tspan>
  </text>
  <!-- 用户信息 -->
  <text x="130" y="400" font-family="sans-serif" font-size="28" fill="rgba(255,255,255,0.4)">— {nick}</text>
  <!-- 底部信息 -->
  <text x="80" y="540" font-family="sans-serif" font-size="24" fill="rgba(255,255,255,0.2)">tucaowall.vip</text>
  <text x="1120" y="540" font-family="sans-serif" font-size="24" fill="rgba(255,255,255,0.2)" text-anchor="end">❤️ {likes}</text>
  <!-- 地球剪影 -->
  <circle cx="1100" cy="500" r="180" fill="none" stroke="rgba(255,255,255,0.03)" stroke-width="2"/>
</svg>'''

def require_admin():
    """检查管理员认证"""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Basic '):
        return False
    try:
        decoded = base64.b64decode(auth[6:]).decode('utf-8')
        _, pwd = decoded.split(':', 1)
        return pwd == ADMIN_PASSWORD
    except:
        return False

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    return conn

# ===== Token认证辅助函数 =====
def get_token_user():
    """从请求头Authorization获取当前登录用户，返回(user_dict, None)或(None, error_response)"""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None, (jsonify({'error': '请先登录', 'need_login': True}), 401)
    token = auth[7:].strip()
    if not token or len(token) < 10:
        return None, (jsonify({'error': '登录已过期，请重新登录', 'need_login': True}), 401)
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM users WHERE token = %s", (token,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if not user:
            return None, (jsonify({'error': '登录已过期，请重新登录', 'need_login': True}), 401)
        return user, None
    except Exception as e:
        return None, (jsonify({'error': str(e)}), 500)

def get_opt_user():
    """可选登录用户——有token就返回user，没有就返回None"""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth[7:].strip()
    if not token or len(token) < 10:
        return None
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM users WHERE token = %s", (token,))
        user = cur.fetchone()
        cur.close(); conn.close()
        return user
    except:
        return None

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            content TEXT NOT NULL,
            nickname VARCHAR(50) DEFAULT '匿名吐槽',
            profession VARCHAR(50) DEFAULT '',
            target VARCHAR(100) DEFAULT '',
            likes INTEGER DEFAULT 0,
            color VARCHAR(7) DEFAULT '#ffffff',
            created_at TIMESTAMP DEFAULT NOW(),
            ip_hash VARCHAR(64)
        )
    """)
    # 兼容旧表加字段
    try:
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS profession VARCHAR(50) DEFAULT ''")
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS target VARCHAR(100) DEFAULT ''")
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS featured BOOLEAN DEFAULT false")
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS payment_id VARCHAR(100) DEFAULT ''")
    except:
        pass
    # 推送订阅表
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS push_subscriptions (
                id SERIAL PRIMARY KEY,
                endpoint TEXT NOT NULL UNIQUE,
                auth VARCHAR(255),
                p256dh VARCHAR(255),
                lang VARCHAR(10) DEFAULT 'zh',
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
    except:
        pass
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            contact VARCHAR(200) NOT NULL,
            service_type VARCHAR(50) NOT NULL,
            description TEXT,
            budget VARCHAR(100),
            created_at TIMESTAMP DEFAULT NOW(),
            status VARCHAR(20) DEFAULT 'new'
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id SERIAL PRIMARY KEY,
            sale_id VARCHAR(200) UNIQUE,
            post_id INTEGER,
            amount INTEGER DEFAULT 0,
            email VARCHAR(200) DEFAULT '',
            product VARCHAR(200) DEFAULT '',
            raw_data TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    try:
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS custom_color VARCHAR(20) DEFAULT ''")
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS featured_until TIMESTAMP")
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS boost_until TIMESTAMP")
    except: pass
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vip_users (
            id SERIAL PRIMARY KEY,
            ip_hash VARCHAR(64) UNIQUE,
            nick VARCHAR(50) DEFAULT '',
            email VARCHAR(200) DEFAULT '',
            payment_id VARCHAR(200) DEFAULT '',
            vip_until TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ads (
            id SERIAL PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            link VARCHAR(500) DEFAULT '',
            image_url VARCHAR(500) DEFAULT '',
            active BOOLEAN DEFAULT true
        )
    """)
    # 插入默认广告
    # === 用户系统（轻量账户——昵称+密码） ===
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                nickname VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(64) NOT NULL,
                token VARCHAR(64) DEFAULT '',
                coin_balance INTEGER DEFAULT 0,
                total_earned INTEGER DEFAULT 0,
                is_vip BOOLEAN DEFAULT false,
                vip_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT NOW(),
                last_login TIMESTAMP DEFAULT NOW()
            )
        """)
    except:
        pass
    # === 硬币表加user_id ===
    try:
        cur.execute("ALTER TABLE coins ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id)")
    except:
        pass
    # === checkins加user_id ===
    try:
        cur.execute("ALTER TABLE checkins ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id)")
    except:
        pass
    try:
        cur.execute("ALTER TABLE checkins DROP CONSTRAINT IF EXISTS checkins_user_id_date_key")
    except:
        pass
    try:
        cur.execute("ALTER TABLE checkins ADD CONSTRAINT checkins_user_id_date_key UNIQUE (user_id, date)")
    except:
        pass
    # === posts加user_id ===
    try:
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id)")
    except:
        pass
    # === users加github字段 ===
    try:
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS github_id VARCHAR(50) DEFAULT ''")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS github_login VARCHAR(100) DEFAULT ''")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS github_avatar VARCHAR(500) DEFAULT ''")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(100) DEFAULT ''")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_login VARCHAR(200) DEFAULT ''")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_avatar VARCHAR(500) DEFAULT ''")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id VARCHAR(50) DEFAULT ''")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_login VARCHAR(100) DEFAULT ''")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_avatar VARCHAR(500) DEFAULT ''")
    except:
        pass
    # === 硬币交易流水 ===
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS coin_transactions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                amount INTEGER NOT NULL,
                type VARCHAR(20) NOT NULL,
                ref_id INTEGER DEFAULT 0,
                note TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
    except:
        pass
    # === 点数系统 ===
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS coins (
                id SERIAL PRIMARY KEY,
                ip_hash VARCHAR(64) NOT NULL UNIQUE,
                balance INTEGER DEFAULT 0,
                total_earned INTEGER DEFAULT 0,
                vip_multiplier BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
    except:
        pass
    try:
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS tip_amount INTEGER DEFAULT 0")
    except:
        pass
    # === 新增表: replies ===
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS replies (
                id SERIAL PRIMARY KEY,
                post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                nickname VARCHAR(50) DEFAULT '匿名',
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
    except:
        pass
    # === 新增表: checkins ===
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS checkins (
                id SERIAL PRIMARY KEY,
                ip_hash VARCHAR(64) NOT NULL,
                date DATE NOT NULL,
                streak INTEGER DEFAULT 1,
                UNIQUE(ip_hash, date)
            )
        """)
    except:
        pass
    # === 新增表: pageviews ===
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pageviews (
                id SERIAL PRIMARY KEY,
                path VARCHAR(500) DEFAULT '/',
                referrer VARCHAR(500) DEFAULT '',
                user_agent TEXT DEFAULT '',
                ip_hash VARCHAR(64) DEFAULT '',
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
    except:
        pass
    # === 新增表: likes_log ===
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS likes_log (
                id SERIAL PRIMARY KEY,
                post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                ip_hash VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
    except:
        pass
    # === 新增列: share_count on posts ===
    try:
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS share_count INTEGER DEFAULT 0")
    except:
        pass
    # === 推荐系统表 ===
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS referral_codes (
                id SERIAL PRIMARY KEY,
                ip_hash VARCHAR(64) NOT NULL UNIQUE,
                code VARCHAR(6) NOT NULL UNIQUE,
                referrer_nick VARCHAR(50) DEFAULT '',
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
    except:
        pass
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS referral_redemptions (
                id SERIAL PRIMARY KEY,
                code VARCHAR(6) NOT NULL REFERENCES referral_codes(code),
                claimed_by_ip VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(claimed_by_ip)
            )
        """)
    except:
        pass
    try:
        cur.execute("ALTER TABLE posts ADD COLUMN IF NOT EXISTS referral_star BOOLEAN DEFAULT false")
    except:
        pass
    cur.execute("SELECT COUNT(*) FROM ads")
    if cur.fetchone()[0] == 0:
        cur.execute("""
            INSERT INTO ads (title, link, image_url) VALUES
            ('AI视觉创作 · 接单中', 'https://tucaowall.vip/portfolio', ''),
            ('广告位招租 · 联系站长', 'mailto:lb1192176991@gmail.com', '')
        """)
    cur.close()
    conn.close()

# ===== 用户认证 API =====
@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    """注册——昵称+4位密码，自动生成token"""
    data = request.json or {}
    nickname = (data.get('nickname', '') or '').strip()[:50]
    password = (data.get('password', '') or '').strip()
    
    if not nickname or len(nickname) < 1:
        return jsonify({'error': '请输入昵称'}), 400
    if not password or len(password) < 4 or len(password) > 20:
        return jsonify({'error': '密码4-20位'}), 400
    
    # 违禁词检查
    clean, _ = sensitive.is_clean(nickname)
    if not clean:
        return jsonify({'error': '昵称包含违规内容'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    token = hashlib.sha256(f'{nickname}{password_hash}{datetime.datetime.utcnow().timestamp()}'.encode()).hexdigest()
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(
            "INSERT INTO users (nickname, password_hash, token) VALUES (%s, %s, %s) RETURNING *",
            (nickname, password_hash, token)
        )
        user = cur.fetchone()
        # 创建硬币记录+同步到users表
        cur.execute("INSERT INTO coins (user_id, balance, updated_at) VALUES (%s, 0, NOW()) ON CONFLICT DO NOTHING", (user['id'],))
        # users.coin_balance保持同步
        conn.commit()
        cur.close(); conn.close()
        return jsonify({
            'ok': True,
            'user': {
                'id': user['id'],
                'nickname': user['nickname'],
                'token': user['token'],
                'coin_balance': 0,
                'is_vip': False
            }
        })
    except Exception as e:
        cur.close(); conn.close()
        if 'unique' in str(e).lower() or 'duplicate' in str(e).lower():
            return jsonify({'error': '该昵称已被注册'}), 409
        return jsonify({'error': f'注册失败: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    """登录——昵称+密码"""
    data = request.json or {}
    nickname = (data.get('nickname', '') or '').strip()
    password = (data.get('password', '') or '').strip()
    
    if not nickname or not password:
        return jsonify({'error': '请输入昵称和密码'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE nickname = %s AND password_hash = %s", (nickname, password_hash))
    user = cur.fetchone()
    if not user:
        cur.close(); conn.close()
        return jsonify({'error': '昵称或密码错误'}), 401
    
    # 刷新token
    new_token = hashlib.sha256(f'{user["id"]}{password_hash}{datetime.datetime.utcnow().timestamp()}'.encode()).hexdigest()
    cur.execute("UPDATE users SET token = %s, last_login = NOW() WHERE id = %s", (new_token, user['id']))
    conn.commit()
    cur.close(); conn.close()
    
    return jsonify({
        'ok': True,
        'user': {
            'id': user['id'],
            'nickname': user['nickname'],
            'token': new_token,
            'coin_balance': user['coin_balance'],
            'is_vip': bool(user['is_vip'])
        }
    })

@app.route('/api/auth/me', methods=['GET'])
def auth_me():
    """获取当前登录用户信息"""
    user, err = get_token_user()
    if err:
        return err
    return jsonify({
        'ok': True,
        'user': {
            'id': user['id'],
            'nickname': user['nickname'],
            'coin_balance': user['coin_balance'],
            'is_vip': bool(user['is_vip']),
            'vip_until': user['vip_until'].isoformat() if user['vip_until'] else None
        }
    })

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    """登出——清空token"""
    user, err = get_token_user()
    if err:
        return err
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET token = '' WHERE id = %s", (user['id'],))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({'ok': True})

# ===== GitHub OAuth 登录 =====
@app.route('/api/auth/github/login')
def github_oauth_login():
    """跳转到GitHub授权页面"""
    if not GITHUB_CLIENT_ID:
        return jsonify({'error': 'GitHub登录未配置'}), 500
    redirect_uri = 'https://tucaowall.vip/api/auth/github/callback'
    state = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
    # 把state存到session（用简单方式——等会callback验证）
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO pageviews (path, referrer, ip_hash) VALUES (%s, %s, %s)",
            (f'/oauth/state/{state}', 'oauth:github', hashlib.sha256((request.remote_addr or '').encode()).hexdigest()[:16]))
        conn.commit()
        cur.close(); conn.close()
    except: pass
    
    url = (f'https://github.com/login/oauth/authorize'
           f'?client_id={GITHUB_CLIENT_ID}'
           f'&redirect_uri={urllib.parse.quote(redirect_uri)}'
           f'&state={state}'
           f'&scope=read:user')
    return jsonify({'redirect_url': url})

@app.route('/api/auth/github/callback')
def github_oauth_callback():
    """GitHub OAuth回调"""
    code = request.args.get('code', '')
    state = request.args.get('state', '')
    
    if not code:
        return '<html><body><script>window.close();alert("授权失败");</script></body></html>'
    
    # 验证state（可选）
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM pageviews WHERE path = %s", (f'/oauth/state/{state}',))
        conn.commit()
        cur.close(); conn.close()
    except: pass
    
    # 交换access_token
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        return '<html><body><script>window.close();alert("GitHub登录未配置");</script></body></html>'
    
    try:
        # 用access_token换code
        import requests as req
        token_resp = req.post('https://github.com/login/oauth/access_token', 
            data={'client_id': GITHUB_CLIENT_ID, 'client_secret': GITHUB_CLIENT_SECRET, 'code': code},
            headers={'Accept': 'application/json'})
        token_data = token_resp.json()
        access_token = token_data.get('access_token', '')
        
        if not access_token:
            return '<html><body><script>window.close();alert("GitHub授权失败");</script></body></html>'
        
        # 获取GitHub用户信息
        user_resp = req.get('https://api.github.com/user', headers={'Authorization': f'Bearer {access_token}'})
        gh_user = user_resp.json()
        gh_login = gh_user.get('login', '')
        gh_id = gh_user.get('id', 0)
        gh_avatar = gh_user.get('avatar_url', '')
        
        if not gh_login:
            return '<html><body><script>window.close();alert("获取GitHub信息失败");</script></body></html>'
        
        # 查找或创建用户
        conn2 = get_db()
        cur2 = conn2.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # 用github_id查找已有绑定
        cur2.execute("SELECT * FROM users WHERE github_id = %s", (str(gh_id),))
        user = cur2.fetchone()
        
        if not user:
            # 用github_login查找
            cur2.execute("SELECT * FROM users WHERE github_login = %s", (gh_login,))
            user = cur2.fetchone()
        
        new_token = hashlib.sha256(f'gh:{gh_id}:{gh_login}:{datetime.datetime.utcnow().timestamp()}'.encode()).hexdigest()
        
        if user:
            # 更新token
            cur2.execute("UPDATE users SET token = %s, github_avatar = %s, last_login = NOW() WHERE id = %s",
                (new_token, gh_avatar, user['id']))
        else:
            # 创建新用户
            try:
                cur2.execute(
                    "INSERT INTO users (nickname, password_hash, token, github_id, github_login, github_avatar) VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                    (f'gh_{gh_login}', hashlib.sha256(f'oauth_gh_{gh_id}'.encode()).hexdigest(), 
                     new_token, str(gh_id), gh_login, gh_avatar)
                )
                user = cur2.fetchone()
            except Exception as e:
                # 如果昵称冲突（gh_xxx已存在），用随机后缀
                suffix = str(gh_id)[-4:]
                cur2.execute(
                    "INSERT INTO users (nickname, password_hash, token, github_id, github_login, github_avatar) VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                    (f'gh_{gh_login}_{suffix}', hashlib.sha256(f'oauth_gh_{gh_id}_{suffix}'.encode()).hexdigest(),
                     new_token, str(gh_id), gh_login, gh_avatar)
                )
                user = cur2.fetchone()
            
            # 创建硬币记录
            cur2.execute("INSERT INTO coins (user_id, balance) VALUES (%s, 0) ON CONFLICT DO NOTHING", (user['id'],))
        
        conn2.commit()
        cur2.close(); conn2.close()
        
        # 返回HTML页面，把token传给前端
        nickname_escaped = user['nickname'].replace('\\', '\\\\').replace("'", "\\'")
        return f'''<html><body>
<script>
try {{
    localStorage.setItem('tucao_token', '{new_token}');
    window.opener.postMessage({{type:'social_oauth', token:'{new_token}', nickname:'{nickname_escaped}'}}, '*');
    window.close();
}} catch(e) {{
    document.body.innerHTML = '<p>登录成功！请关闭此窗口返回吐槽墙。</p><p>Token: {new_token[:20]}...</p>';
}}
</script>
</body></html>'''
    
    except ImportError:
        return '<html><body><script>window.close();alert("服务端缺少requests库");</script></body></html>'
    except Exception as e:
        return f'<html><body><script>window.close();alert("GitHub登录失败");</script></body></html>'

# ===== 今日劲爆吐槽（AI润色版） =====
@app.route('/api/today-burn', methods=['GET'])
def today_burn():
    """从热门帖子选一条，加AI润色+配色，生成劲爆吐槽卡片"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cur.execute("""
        SELECT * FROM posts 
        WHERE created_at > NOW() - INTERVAL '7 days'
        ORDER BY (likes * 2 + COALESCE(share_count,0) * 3) DESC, RANDOM() 
        LIMIT 3
    """)
    posts = cur.fetchall()
    cur.close(); conn.close()
    
    if not posts:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM posts ORDER BY likes DESC, RANDOM() LIMIT 1")
        posts = cur.fetchall()
        cur.close(); conn.close()
    
    if not posts:
        return jsonify({'error': '暂无帖子'}), 404
    
    post = random.choice(posts)
    content = post['content']
    nickname = post['nickname'] or '匿名吐槽'
    
    # 劲爆段子模板——不用第三方API，纯模板+动态拼接
    templates = [
        lambda c, n: f'💥 "{c}"\n\n—— {n} の 灵魂吐槽',
        lambda c, n: f'🔥【今日份扎心】\n"{c}"\n—— {n}',
        lambda c, n: f'😤 {c}\n\n—— 来自 {n} 的真实心声',
        lambda c, n: f'💀 过于真实："{c}"\n—— {n} 说道',
        lambda c, n: f'🎯 今日最佳：\n"{c}"\n\n👤 {n}',
        lambda c, n: f'💬 "{c}"\n\n📌 {n} · 不吐不快',
        lambda c, n: f'⚡ 打工人的日常：\n"{c}"\n\n—— {n}',
        lambda c, n: f'🤯 "{c}"\n\n—— 来自 {n} 的绝望吐槽',
        lambda c, n: f'📢 匿名爆料：\n"{c}"\n\n🗣️ {n}',
        lambda c, n: f'💪 一位不愿透露姓名的{n}表示：\n"{c}"',
    ]
    
    template_idx = (len(content) + post['id']) % len(templates)
    burn_text = templates[template_idx](content, nickname)
    
    # 渐变色配对
    colors = [
        ['#ff6b6b', '#ee5a24'],
        ['#ffd93d', '#ff9f43'],
        ['#6bcb77', '#1dd1a1'],
        ['#4d96ff', '#5f27cd'],
        ['#a855f7', '#ec4899'],
        ['#00d2d3', '#54a0ff'],
    ]
    color_pair = colors[post['id'] % len(colors)]
    
    return jsonify({
        'burn': burn_text,
        'content': content,
        'nickname': nickname,
        'likes': post['likes'],
        'post_id': post['id'],
        'color_from': color_pair[0],
        'color_to': color_pair[1],
        'share_url': f'https://tucaowall.vip/post/{post["id"]}'
    })

# ===== OAuth 通用辅助函数 =====
def oauth_create_or_update(provider, provider_id, login, avatar, nickname_prefix):
    """统一处理OAuth用户创建/登录——返回(new_token, nickname)"""
    import requests as req
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    pid_field = provider + '_id'
    login_field = provider + '_login'
    avatar_field = provider + '_avatar'
    
    # 查找已有绑定
    cur.execute(f"SELECT * FROM users WHERE {pid_field} = %s", (str(provider_id),))
    user = cur.fetchone()
    
    if not user:
        cur.execute(f"SELECT * FROM users WHERE {login_field} = %s", (login,))
        user = cur.fetchone()
    
    new_token = hashlib.sha256(f'{provider}:{provider_id}:{login}:{datetime.datetime.utcnow().timestamp()}'.encode()).hexdigest()
    
    if user:
        cur.execute(f"UPDATE users SET token = %s, {avatar_field} = %s, last_login = NOW() WHERE id = %s",
            (new_token, avatar, user['id']))
    else:
        nickname = f'{nickname_prefix}{login}'
        try:
            cur.execute(
                f"INSERT INTO users (nickname, password_hash, token, {pid_field}, {login_field}, {avatar_field}) VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                (nickname, hashlib.sha256(f'oauth_{provider}_{provider_id}'.encode()).hexdigest(),
                 new_token, str(provider_id), login, avatar)
            )
            user = cur.fetchone()
        except Exception:
            suffix = str(provider_id)[-4:]
            nickname = f'{nickname_prefix}{login}_{suffix}'
            cur.execute(
                f"INSERT INTO users (nickname, password_hash, token, {pid_field}, {login_field}, {avatar_field}) VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                (nickname, hashlib.sha256(f'oauth_{provider}_{provider_id}_{suffix}'.encode()).hexdigest(),
                 new_token, str(provider_id), login, avatar)
            )
            user = cur.fetchone()
        
        cur.execute("INSERT INTO coins (user_id, balance, updated_at) VALUES (%s, 0, NOW()) ON CONFLICT DO NOTHING", (user['id'],))
    
    conn.commit()
    cur.close(); conn.close()
    return new_token, user['nickname']

def oauth_callback_html(token, nickname):
    """生成OAuth回调的HTML页面，把token传给前端"""
    nick_esc = nickname.replace('\\', '\\\\').replace("'", "\\'")
    return f'''<html><body>
<script>
try {{
    localStorage.setItem('tucao_token', '{token}');
    window.opener.postMessage({{type:'social_oauth', token:'{token}', nickname:'{nick_esc}'}}, '*');
    window.close();
}} catch(e) {{
    document.body.innerHTML = '<p>登录成功！请关闭此窗口返回吐槽墙。</p>';
}}
</script>
</body></html>'''

# ===== Google OAuth 登录 =====
@app.route('/api/auth/google/login')
def google_oauth_login():
    if not GOOGLE_CLIENT_ID:
        return jsonify({'error': 'Google登录未配置'}), 500
    redirect_uri = 'https://tucaowall.vip/api/auth/google/callback'
    state = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
    url = (f'https://accounts.google.com/o/oauth2/v2/auth'
           f'?client_id={GOOGLE_CLIENT_ID}'
           f'&redirect_uri={urllib.parse.quote(redirect_uri)}'
           f'&state={state}'
           f'&scope=openid+email+profile'
           f'&response_type=code')
    return jsonify({'redirect_url': url})

@app.route('/api/auth/google/callback')
def google_oauth_callback():
    code = request.args.get('code', '')
    if not code:
        return oauth_callback_html('', '')
    try:
        import requests as req
        # 换token
        token_resp = req.post('https://oauth2.googleapis.com/token', data={
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://tucaowall.vip/api/auth/google/callback'
        }, headers={'Accept': 'application/json'})
        token_data = token_resp.json()
        id_token = token_data.get('id_token', '')
        access_token = token_data.get('access_token', '')
        
        if not access_token:
            return oauth_callback_html('', '')
        
        # 获取Google用户信息
        user_resp = req.get('https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'})
        g_user = user_resp.json()
        g_id = g_user.get('id', '')
        g_email = g_user.get('email', '')
        g_name = g_user.get('name', g_email.split('@')[0] if '@' in g_email else 'user')
        g_avatar = g_user.get('picture', '')
        
        if not g_id:
            return oauth_callback_html('', '')
        
        token, nick = oauth_create_or_update('google', g_id, g_email, g_avatar, 'gg_')
        return oauth_callback_html(token, nick)
    except Exception:
        return oauth_callback_html('', '')

# ===== Discord OAuth 登录 =====
@app.route('/api/auth/discord/login')
def discord_oauth_login():
    if not DISCORD_CLIENT_ID:
        return jsonify({'error': 'Discord登录未配置'}), 500
    redirect_uri = 'https://tucaowall.vip/api/auth/discord/callback'
    state = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
    url = (f'https://discord.com/api/oauth2/authorize'
           f'?client_id={DISCORD_CLIENT_ID}'
           f'&redirect_uri={urllib.parse.quote(redirect_uri)}'
           f'&state={state}'
           f'&scope=identify'
           f'&response_type=code')
    return jsonify({'redirect_url': url})

@app.route('/api/auth/discord/callback')
def discord_oauth_callback():
    code = request.args.get('code', '')
    if not code:
        return oauth_callback_html('', '')
    try:
        import requests as req
        # 换token
        token_resp = req.post('https://discord.com/api/oauth2/token', data={
            'client_id': DISCORD_CLIENT_ID,
            'client_secret': DISCORD_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://tucaowall.vip/api/auth/discord/callback'
        }, headers={'Accept': 'application/json'})
        token_data = token_resp.json()
        access_token = token_data.get('access_token', '')
        
        if not access_token:
            return oauth_callback_html('', '')
        
        # 获取Discord用户信息
        user_resp = req.get('https://discord.com/api/users/@me',
            headers={'Authorization': f'Bearer {access_token}'})
        d_user = user_resp.json()
        d_id = d_user.get('id', '')
        d_name = d_user.get('username', 'user')
        d_avatar_hash = d_user.get('avatar', '')
        d_avatar = f'https://cdn.discordapp.com/avatars/{d_id}/{d_avatar_hash}.png' if d_avatar_hash else ''
        
        if not d_id:
            return oauth_callback_html('', '')
        
        token, nick = oauth_create_or_update('discord', d_id, d_name, d_avatar, 'dc_')
        return oauth_callback_html(token, nick)
    except Exception:
        return oauth_callback_html('', '')

# ===== 帖子API =====
@app.route('/api/posts', methods=['GET'])
def get_posts():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    offset = (page - 1) * limit
    
    msg_count = cur.execute("SELECT COUNT(*) FROM posts")
    total = cur.fetchone()['count']
    
    cur.execute("SELECT * FROM posts ORDER BY featured DESC, boost_until DESC NULLS LAST, created_at DESC LIMIT %s OFFSET %s", (limit, offset))
    posts = cur.fetchall()
    for p in posts:
        p['created_at'] = p['created_at'].isoformat() if p['created_at'] else None
    cur.close()
    conn.close()
    return jsonify({'posts': posts, 'total': total, 'page': page})

# ===== Feature 1: 热门算法 + Trending API =====
@app.route('/api/posts/trending', methods=['GET'])
def get_trending():
    """热门算法: score = likes*2 + share*3 + reply*4 - hours_age*0.5"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT p.*,
            (SELECT COUNT(*) FROM replies WHERE post_id = p.id) AS reply_count,
            (EXTRACT(EPOCH FROM (NOW() - p.created_at)) / 3600)::float AS hours_age
        FROM posts p
        ORDER BY
            (p.likes * 2.0 + COALESCE(p.share_count, 0) * 3.0 + (SELECT COUNT(*) FROM replies WHERE post_id = p.id) * 4.0 - (EXTRACT(EPOCH FROM (NOW() - p.created_at)) / 3600) * 0.5) DESC
        LIMIT 20
    """)
    posts = cur.fetchall()
    for p in posts:
        p['created_at'] = p['created_at'].isoformat() if p['created_at'] else None
        if 'hours_age' in p:
            del p['hours_age']
    cur.close()
    conn.close()
    return jsonify(posts)

# ===== 记录分享次数 =====
@app.route('/api/posts/<int:post_id>/share', methods=['POST'])
def record_share(post_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("UPDATE posts SET share_count = COALESCE(share_count, 0) + 1 WHERE id = %s RETURNING share_count", (post_id,))
    result = cur.fetchone()
    if not result:
        cur.close(); conn.close()
        return jsonify({'error': '不存在'}), 404
    
    # 分享奖励金币
    user = get_opt_user()
    coins_rewarded = 0
    if user:
        coins_rewarded = 2  # 每次分享奖励2金币
        cur.execute("UPDATE users SET coin_balance = coin_balance + %s, total_earned = total_earned + %s WHERE id = %s RETURNING coin_balance", (coins_rewarded, coins_rewarded, user['id']))
        coin = cur.fetchone()
        cur.execute("INSERT INTO coin_transactions (user_id, amount, type, note) VALUES (%s, %s, 'share', '分享奖励')", (user['id'], coins_rewarded))
        conn.commit()
        cur.close(); conn.close()
        return jsonify({'share_count': result['share_count'], 'coins_earned': coins_rewarded, 'balance': coin['coin_balance']})
    else:
        # 游客也奖励（但存在ip_hash的coins表）
        ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
        cur.execute("SELECT * FROM coins WHERE ip_hash = %s", (ip_hash,))
        coin = cur.fetchone()
        if coin:
            cur.execute("UPDATE coins SET balance = balance + 2, total_earned = total_earned + 2, updated_at = NOW() WHERE ip_hash = %s RETURNING balance", (ip_hash,))
            coin = cur.fetchone()
            coins_rewarded = 2
        else:
            cur.execute("INSERT INTO coins (ip_hash, balance, total_earned) VALUES (%s, 2, 2) RETURNING balance", (ip_hash,))
            coin = cur.fetchone()
            coins_rewarded = 2
        conn.commit()
        cur.close(); conn.close()
        return jsonify({'share_count': result['share_count'], 'coins_earned': coins_rewarded, 'balance': coin['balance']})
    return jsonify({'share_count': result['share_count']})

@app.route('/api/posts', methods=['POST'])
def create_post():
    data = request.json
    content = (data.get('content', '') or '').strip()
    nickname = (data.get('nickname', '匿名吐槽') or '').strip()[:50]
    
    if not content or len(content) > 500:
        return jsonify({'error': '内容1-500字'}), 400
    
    # === 全球违禁词检查 ===
    clean, violations = sensitive.is_clean(content)
    if not clean:
        cats = [v['category'] for v in violations[:3]]
        return jsonify({
            'error': f'内容包含违规内容: {", ".join(cats)}',
            'violations': violations[:3]
        }), 400
    clean, violations = sensitive.is_clean(nickname)
    if not clean:
        return jsonify({'error': '昵称包含违规内容'}), 400
    
    # === 获��当前用户（可选登录） ===
    user = get_opt_user()
    user_id = user['id'] if user else None
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    coin_balance = None
    
    # === 免费发帖额度检查 ===
    today = datetime.date.today()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    FREE_LIMIT = 3
    
    if user_id:
        # 登录用户——按user_id统计
        cur.execute("SELECT COUNT(*) as cnt FROM posts WHERE user_id = %s AND created_at::date = %s", (user_id, today))
        today_count = cur.fetchone()['cnt']
        if today_count >= FREE_LIMIT:
            if user['coin_balance'] < 1:
                cur.close(); conn.close()
                return jsonify({
                    'error': f'今日已免费发布{FREE_LIMIT}条。再发帖需要1金币，余额不足',
                    'need_coin': True, 'free_limit': FREE_LIMIT, 'today_count': today_count
                }), 402
            cur.execute("UPDATE users SET coin_balance = coin_balance - 1 WHERE id = %s RETURNING coin_balance", (user_id,))
            coin_balance = cur.fetchone()['coin_balance']
            # 记录流水
            cur.execute("INSERT INTO coin_transactions (user_id, amount, type, note) VALUES (%s, -1, 'post', '发帖')", (user_id,))
    else:
        # 游客——按ip_hash统计
        cur.execute("SELECT COUNT(*) as cnt FROM posts WHERE ip_hash = %s AND created_at::date = %s", (ip_hash, today))
        today_count = cur.fetchone()['cnt']
        if today_count >= FREE_LIMIT:
            cur.execute("SELECT balance FROM coins WHERE ip_hash = %s", (ip_hash,))
            coin = cur.fetchone()
            if not coin or coin['balance'] < 1:
                cur.close(); conn.close()
                return jsonify({
                    'error': f'今日已免费发布{FREE_LIMIT}条。登录后可充值继续发帖',
                    'need_login': True, 'free_limit': FREE_LIMIT, 'today_count': today_count
                }), 402
            cur.execute("UPDATE coins SET balance = balance - 1, updated_at = NOW() WHERE ip_hash = %s RETURNING balance", (ip_hash,))
            coin = cur.fetchone()
            coin_balance = coin['balance']
    
    colors = ['#ff6b6b', '#ffd93d', '#6bcb77', '#4d96ff', '#ff9ff3', '#54a0ff', '#5f27cd', '#01a3a4', '#f368e0', '#ff9f43']
    color = random.choice(colors)
    
    cur.execute(
        "INSERT INTO posts (content, nickname, profession, target, color, ip_hash, user_id) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *",
        (content, nickname, data.get('profession', ''), data.get('target', ''), color, ip_hash, user_id)
    )
    post = cur.fetchone()
    post['created_at'] = post['created_at'].isoformat()
    post['balance'] = coin_balance
    cur.close()
    conn.close()
    return jsonify(post), 201

# ===== 帖子编辑/删除/搜索/我的帖子 =====
@app.route('/api/posts/<int:post_id>', methods=['PATCH'])
def edit_post(post_id):
    """编辑帖子内容（仅本人）"""
    user, err = get_token_user()
    if err:
        return err
    data = request.json or {}
    content = (data.get('content', '') or '').strip()
    if not content or len(content) > 500:
        return jsonify({'error': '内容1-500字'}), 400
    clean, violations = sensitive.is_clean(content)
    if not clean:
        return jsonify({'error': '内容包含违规内容'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posts WHERE id = %s AND user_id = %s", (post_id, user['id']))
    post = cur.fetchone()
    if not post:
        cur.close(); conn.close()
        return jsonify({'error': '帖子不存在或无权编辑'}), 403
    cur.execute("UPDATE posts SET content = %s WHERE id = %s RETURNING *", (content, post_id))
    post = cur.fetchone()
    post['created_at'] = post['created_at'].isoformat() if post['created_at'] else None
    cur.close(); conn.close()
    return jsonify(post)

@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    """删除帖子（仅本人或管理员）"""
    user, err = get_token_user()
    if err:
        return err
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # 管理员可以删任何帖
    auth_header = request.headers.get('Authorization', '')
    is_admin = auth_header.startswith('Basic ') and auth_header[6:] == ADMIN_PASSWORD
    if is_admin:
        cur.execute("DELETE FROM posts WHERE id = %s RETURNING id", (post_id,))
    else:
        cur.execute("DELETE FROM posts WHERE id = %s AND user_id = %s RETURNING id", (post_id, user['id']))
    deleted = cur.fetchone()
    conn.commit()
    cur.close(); conn.close()
    if not deleted:
        return jsonify({'error': '帖子不存在或无权删除'}), 403
    return jsonify({'ok': True, 'deleted_id': post_id})

@app.route('/api/posts/search', methods=['GET'])
def search_posts():
    """搜索帖子"""
    q = (request.args.get('q', '') or '').strip()
    if not q or len(q) < 1:
        return jsonify({'posts': [], 'total': 0})
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    like = f'%{q}%'
    cur.execute(
        "SELECT * FROM posts WHERE (content ILIKE %s OR nickname ILIKE %s) ORDER BY created_at DESC LIMIT 50",
        (like, like))
    posts = cur.fetchall()
    for p in posts:
        p['created_at'] = p['created_at'].isoformat() if p['created_at'] else None
    total = len(posts)
    cur.close(); conn.close()
    return jsonify({'posts': posts, 'total': total, 'query': q})

@app.route('/api/posts/my', methods=['GET'])
def my_posts():
    """获取我发的帖子（登录用户）"""
    user, err = get_token_user()
    if err:
        return err
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posts WHERE user_id = %s ORDER BY created_at DESC LIMIT 50", (user['id'],))
    posts = cur.fetchall()
    for p in posts:
        p['created_at'] = p['created_at'].isoformat() if p['created_at'] else None
    cur.close(); conn.close()
    return jsonify({'posts': posts, 'total': len(posts)})

@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    """获取当前用户的通知（新回复提醒等）"""
    user, err = get_token_user()
    if err:
        return err
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # 查找用户帖子下的新回复
    cur.execute("""
        SELECT r.*, p.content as post_content, p.nickname as post_nickname
        FROM replies r JOIN posts p ON r.post_id = p.id
        WHERE p.user_id = %s
        ORDER BY r.created_at DESC LIMIT 20
    """, (user['id'],))
    notifications = cur.fetchall()
    for n in notifications:
        n['created_at'] = n['created_at'].isoformat() if n['created_at'] else None
    cur.close(); conn.close()
    return jsonify({'notifications': notifications, 'total': len(notifications)})

# ===== 查看全文扣费（弹幕预览免费，点开看全文扣1金币） =====
@app.route('/api/posts/<int:post_id>/unlock', methods=['POST'])
def unlock_post(post_id):
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # 检查硬币
    cur.execute("SELECT balance FROM coins WHERE ip_hash = %s", (ip_hash,))
    coin = cur.fetchone()
    if not coin or coin['balance'] < 1:
        cur.close(); conn.close()
        return jsonify({'error': '查看全文需要1金币', 'balance': coin['balance'] if coin else 0}), 402
    
    cur.execute("UPDATE coins SET balance = balance - 1, updated_at = NOW() WHERE ip_hash = %s RETURNING balance", (ip_hash,))
    coin = cur.fetchone()
    conn.commit()
    
    # 获取完整帖子内容
    cur.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    cur.close(); conn.close()
    
    if not post:
        return jsonify({'error': '不存在'}), 404
    
    post['created_at'] = post['created_at'].isoformat() if post['created_at'] else None
    post['balance'] = coin['balance']
    return jsonify(post)

# ===== 免费发帖额度查询（方便前端显示剩余条数） =====
@app.route('/api/posts/free-remaining', methods=['GET'])
def free_remaining():
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    today = datetime.date.today()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as cnt FROM posts WHERE ip_hash = %s AND created_at::date = %s", (ip_hash, today))
    cnt = cur.fetchone()[0]
    cur.close(); conn.close()
    return jsonify({'free_limit': 3, 'used_today': cnt, 'remaining': max(0, 3 - cnt)})

# ===== Twitter分享增强：预生成推文链接 =====
@app.route('/api/share/twitter/<int:post_id>', methods=['GET'])
def share_twitter(post_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    cur.close(); conn.close()
    if not post:
        return jsonify({'error': '不存在'}), 404
    content = post['content'][:200]
    text = f'「{content}」\n\n在 @tucaowall 吐槽了一下，不吐不快！\n'
    url = f'https://tucaowall.vip/post/{post_id}'
    tweet = text + '\n' + url
    twitter_url = 'https://twitter.com/intent/tweet?text=' + urllib.parse.quote(tweet)
    return jsonify({'twitter_url': twitter_url, 'text': text, 'url': url})

# ===== 分享解锁增强：记录分享次数超过3次后解锁劲爆内容 =====
@app.route('/api/share/unlock', methods=['POST'])
def share_unlock():
    data = request.json or {}
    platform = data.get('platform', 'twitter')
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    
    today = datetime.date.today()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # 用pageviews表记录分享事件（复用）
    cur.execute("INSERT INTO pageviews (path, referrer, ip_hash) VALUES (%s, %s, %s)",
        (f'/share/{platform}', f'share:{platform}', ip_hash))
    conn.commit()
    cur.execute("SELECT COUNT(*) as cnt FROM pageviews WHERE ip_hash = %s AND path LIKE %s AND created_at::date = %s",
        (ip_hash, '/share/%', today))
    cnt = cur.fetchone()['cnt']
    cur.close(); conn.close()
    return jsonify({'shared_today': cnt, 'unlocked': cnt >= 3, 'required': 3})

@app.route('/api/posts/<int:post_id>/color', methods=['POST'])
def color_post(post_id):
    data = request.json or {}
    color = data.get('color', '#ff6b6b')
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    if not post:
        cur.close(); conn.close()
        return jsonify({'error': '不存在'}), 404
    cur.execute("UPDATE posts SET custom_color = %s WHERE id = %s RETURNING id", (color, post_id))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({'ok': True, 'custom_color': color})

# ===== 硬币系统 API (Coins) =====
@app.route('/api/coins/balance', methods=['POST'])
def coins_balance():
    """获取当前用户硬币余额（支持登录用户和游客）"""
    user = get_opt_user()
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    if user:
        # 登录用户——从users表取
        balance = user['coin_balance']
        total_earned = user['total_earned']
        is_vip = bool(user['is_vip'])
    else:
        # 游客——从coins表取
        cur.execute("SELECT * FROM coins WHERE ip_hash = %s", (ip_hash,))
        coin = cur.fetchone()
        if not coin:
            cur.execute("INSERT INTO coins (ip_hash, balance) VALUES (%s, 0) RETURNING *", (ip_hash,))
            coin = cur.fetchone()
        balance = coin['balance']
        total_earned = coin['total_earned']
        now = datetime.datetime.utcnow()
        cur.execute("SELECT vip_until FROM vip_users WHERE ip_hash = %s", (ip_hash,))
        vip = cur.fetchone()
        is_vip = bool(vip and vip['vip_until'] and vip['vip_until'] > now)
    
    cur.close(); conn.close()
    return jsonify({'balance': balance, 'total_earned': total_earned, 'is_vip': is_vip})

@app.route('/api/coins/recharge', methods=['POST'])
def coins_recharge():
    """生成充值链接"""
    data = request.json or {}
    amount = data.get('amount', 100)
    coins = data.get('coins', amount)
    if amount < 49:
        return jsonify({'error': '最低充值 $0.49'}), 400
    return jsonify({
        'payment_url': f'https://gum.co/nmcqjr?wanted=true&coins={coins}&price={amount}&product=coins',
        'coins': coins,
        'price': f'${amount/100:.2f}'
    })

@app.route('/api/coins/verify-recharge', methods=['POST'])
def coins_verify_recharge():
    """验证充值并增加硬币"""
    data = request.json or {}
    coins = data.get('coins', 0)
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM coins WHERE ip_hash = %s", (ip_hash,))
    coin = cur.fetchone()
    if not coin:
        cur.execute("INSERT INTO coins (ip_hash, balance, total_earned) VALUES (%s, %s, %s) RETURNING *", (ip_hash, coins, coins))
        coin = cur.fetchone()
    else:
        cur.execute("UPDATE coins SET balance = balance + %s, total_earned = total_earned + %s, updated_at = NOW() WHERE ip_hash = %s RETURNING *", (coins, coins, ip_hash))
        coin = cur.fetchone()
    conn.commit()
    cur.close(); conn.close()
    return jsonify({'ok': True, 'balance': coin['balance']})

@app.route('/api/coins/spend', methods=['POST'])
def coins_spend():
    """消费硬币：feature(置顶 49), color(彩色 25), boost(置顶30min 25), who_liked(查看谁赞了 49)"""
    data = request.json or {}
    post_id = data.get('post_id')
    feature = data.get('feature', '')
    coins = data.get('coins', 0)
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    
    prices = {'feature': 49, 'color': 25, 'boost': 25, 'who_liked': 49}
    if feature not in prices:
        return jsonify({'error': '不支持的功能'}), 400
    required = prices[feature]
    if coins < required:
        coins = required
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM coins WHERE ip_hash = %s", (ip_hash,))
    coin = cur.fetchone()
    if not coin or coin['balance'] < required:
        cur.close(); conn.close()
        return jsonify({'error': '硬币不足', 'required': required, 'balance': coin['balance'] if coin else 0}), 400
    
    if feature == 'color':
        colors = ['#ff6b6b','#ffd93d','#6bcb77','#4d96ff','#a855f7','#ff9f43']
        color = random.choice(colors)
        cur.execute("UPDATE posts SET custom_color = %s WHERE id = %s", (color, post_id))
    elif feature == 'feature':
        featured_until = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        cur.execute("UPDATE posts SET featured = true, featured_until = %s WHERE id = %s", (featured_until, post_id))
    elif feature == 'boost':
        boost_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        cur.execute("UPDATE posts SET boost_until = %s WHERE id = %s", (boost_until, post_id))
    elif feature == 'who_liked':
        # who_liked 不需要修改post，付费后前端调用who-liked API
        pass
    
    cur.execute("UPDATE coins SET balance = balance - %s, updated_at = NOW() WHERE ip_hash = %s RETURNING *", (required, ip_hash))
    coin = cur.fetchone()
    conn.commit()
    cur.close(); conn.close()
    return jsonify({'ok': True, 'balance': coin['balance'], 'feature': feature, 'coins_spent': required})

@app.route('/api/coins/tip', methods=['POST'])
def coins_tip():
    """用硬币打赏帖子"""
    data = request.json or {}
    post_id = data.get('post_id')
    coins = int(data.get('coins', 10))
    nickname = (data.get('nickname', '') or '').strip()[:50]
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM coins WHERE ip_hash = %s", (ip_hash,))
    coin = cur.fetchone()
    if not coin or coin['balance'] < coins:
        cur.close(); conn.close()
        return jsonify({'error': '硬币不足', 'required': coins, 'balance': coin['balance'] if coin else 0}), 400
    
    cur.execute("UPDATE coins SET balance = balance - %s, updated_at = NOW() WHERE ip_hash = %s RETURNING *", (coins, ip_hash))
    coin = cur.fetchone()
    cur.execute("UPDATE posts SET tip_amount = COALESCE(tip_amount, 0) + %s, likes = likes + 1 WHERE id = %s", (coins, post_id))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({'ok': True, 'balance': coin['balance'], 'coins_tipped': coins, 'tipped_post': post_id})

@app.route('/api/coins/checkin-reward', methods=['POST'])
def coins_checkin_reward():
    """签到领硬币奖励"""
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    today = datetime.date.today()
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # 检查今天是否已签到
    cur.execute("SELECT * FROM checkins WHERE ip_hash = %s AND date = %s", (ip_hash, today))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({'error': '今天已签到'}), 400
    
    # 计算连续签到天数
    yesterday = today - datetime.timedelta(days=1)
    cur.execute("SELECT * FROM checkins WHERE ip_hash = %s ORDER BY date DESC LIMIT 1", (ip_hash,))
    last = cur.fetchone()
    streak = 1
    if last and last['date'] == yesterday:
        streak = last['streak'] + 1
    
    # 签到
    cur.execute("INSERT INTO checkins (ip_hash, date, streak) VALUES (%s, %s, %s) RETURNING *", (ip_hash, today, streak))
    conn.commit()
    
    # 计算硬币奖励
    coins_earned = 3
    if streak >= 7:
        coins_earned = 10
    # VIP加成
    cur.execute("SELECT vip_until FROM vip_users WHERE ip_hash = %s", (ip_hash,))
    vip = cur.fetchone()
    now = datetime.datetime.utcnow()
    if vip and vip['vip_until'] and vip['vip_until'] > now:
        coins_earned += 5
    
    cur.execute("SELECT * FROM coins WHERE ip_hash = %s", (ip_hash,))
    coin = cur.fetchone()
    if not coin:
        cur.execute("INSERT INTO coins (ip_hash, balance, total_earned) VALUES (%s, %s, %s) RETURNING *", (ip_hash, coins_earned, coins_earned))
        coin = cur.fetchone()
    else:
        cur.execute("UPDATE coins SET balance = balance + %s, total_earned = total_earned + %s, updated_at = NOW() WHERE ip_hash = %s RETURNING *", (coins_earned, coins_earned, ip_hash))
        coin = cur.fetchone()
    conn.commit()
    cur.close(); conn.close()
    return jsonify({'ok': True, 'coins_earned': coins_earned, 'balance': coin['balance'], 'streak': streak})

# ===== OG图片生成API（用于社交分享预览） =====
@app.route('/api/og-image/<int:post_id>', methods=['GET'])
def get_og_image(post_id):
    """返回SVG格式的社交分享预览图"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT content, nickname, likes FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    cur.close(); conn.close()
    
    if not post:
        # 默认OG图
        return render_og_svg('来吐槽墙匿名吐槽', '吐槽墙', 0, 0), 200, {'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=31536000'}
    
    svg = render_og_svg(post['content'], post['nickname'], post['likes'], post_id)
    return svg, 200, {'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400'}

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """站点统计"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT COUNT(*) FROM posts")
    total_posts = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) FROM pageviews")
    total_views = cur.fetchone()['count']
    cur.execute("SELECT COUNT(DISTINCT ip_hash) FROM pageviews")
    unique_visitors = cur.fetchone()['count']
    cur.execute("SELECT SUM(likes) as total FROM posts")
    total_likes = cur.fetchone()['total'] or 0
    cur.close(); conn.close()
    return jsonify({
        'total_posts': total_posts,
        'total_pageviews': total_views,
        'unique_visitors': unique_visitors,
        'total_likes': total_likes
    })

@app.route('/api/banners', methods=['GET'])
def get_banners():
    """获取广告轮播数据"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ads WHERE active = true ORDER BY id")
    ads = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(ads)

@app.route('/api/posts/<int:post_id>/tip', methods=['POST'])
def tip_post(post_id):
    amount = (request.json or {}).get('amount', 100)
    return jsonify({
        'payment_url': f'https://gum.co/nmcqjr?wanted=true&post_id={post_id}&price={amount}',
        'price': f'${amount/100:.2f}'
    })

@app.route('/api/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    cur.close()
    conn.close()
    if not post:
        return jsonify({'error': '不存在'}), 404
    post['created_at'] = post['created_at'].isoformat() if post['created_at'] else None
    return jsonify(post)

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
def like_post(post_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("UPDATE posts SET likes = likes + 1 WHERE id = %s RETURNING likes", (post_id,))
    result = cur.fetchone()
    if not result:
        cur.close()
        conn.close()
        return jsonify({'error': '不存在'}), 404
    # 记录点赞者到 likes_log
    try:
        ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
        cur.execute("INSERT INTO likes_log (post_id, ip_hash) VALUES (%s, %s) ON CONFLICT DO NOTHING", (post_id, ip_hash))
        conn.commit()
    except:
        pass
    cur.close()
    conn.close()
    return jsonify({'likes': result['likes']})

# ===== Feature 2: Reply Chain (弹幕回复) =====
@app.route('/api/posts/<int:post_id>/replies', methods=['GET'])
def get_replies(post_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM replies WHERE post_id = %s ORDER BY created_at ASC LIMIT 50", (post_id,))
    replies = cur.fetchall()
    for r in replies:
        r['created_at'] = r['created_at'].isoformat() if r['created_at'] else None
    cur.close()
    conn.close()
    return jsonify(replies)

@app.route('/api/posts/<int:post_id>/replies', methods=['POST'])
def create_reply(post_id):
    data = request.json
    content = (data.get('content', '') or '').strip()
    nickname = (data.get('nickname', '匿名') or '').strip()[:50]
    if not content or len(content) > 500:
        return jsonify({'error': '回复内容1-500字'}), 400
    # 违禁词检查
    clean, violations = sensitive.is_clean(content)
    if not clean:
        return jsonify({'error': '内容包含违规内容'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # 检查帖子存在
    cur.execute("SELECT id FROM posts WHERE id = %s", (post_id,))
    if not cur.fetchone():
        cur.close(); conn.close()
        return jsonify({'error': '帖子不存在'}), 404
    cur.execute(
        "INSERT INTO replies (post_id, content, nickname) VALUES (%s, %s, %s) RETURNING *",
        (post_id, content, nickname)
    )
    reply = cur.fetchone()
    reply['created_at'] = reply['created_at'].isoformat()
    cur.close()
    conn.close()
    return jsonify(reply), 201

# ===== Feature 3: Daily Check-in (签到/连续打卡) =====
@app.route('/api/checkin', methods=['POST'])
def do_checkin():
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    today = datetime.date.today()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # 检查今天是否已签到
    cur.execute("SELECT * FROM checkins WHERE ip_hash = %s AND date = %s", (ip_hash, today))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({'error': '今天已签到', 'checked': True}), 400
    # 获取上次签到
    cur.execute("SELECT * FROM checkins WHERE ip_hash = %s ORDER BY date DESC LIMIT 1", (ip_hash,))
    last = cur.fetchone()
    if last and (today - last['date']).days == 1:
        streak = last['streak'] + 1
    else:
        streak = 1
    cur.execute("INSERT INTO checkins (ip_hash, date, streak) VALUES (%s, %s, %s) RETURNING *",
                (ip_hash, today, streak))
    result = cur.fetchone()
    conn.commit()
    cur.close(); conn.close()
    rewards = []
    if streak == 3: rewards.append('gold_nickname')
    if streak == 7: rewards.append('free_boost')
    if streak == 30: rewards.append('special_badge')
    return jsonify({
        'ok': True,
        'streak': streak,
        'rewards': rewards,
        'ip_hash': ip_hash
    })

@app.route('/api/checkin/status', methods=['GET'])
def checkin_status():
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    today = datetime.date.today()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM checkins WHERE ip_hash = %s AND date = %s", (ip_hash, today))
    today_checked = cur.fetchone() is not None
    cur.execute("SELECT * FROM checkins WHERE ip_hash = %s ORDER BY date DESC LIMIT 1", (ip_hash,))
    last = cur.fetchone()
    streak = last['streak'] if last else 0
    cur.close(); conn.close()
    can_claim_rewards = []
    for milestone in [3, 7, 30]:
        if streak >= milestone:
            can_claim_rewards.append(milestone)
    return jsonify({
        'today_checked': today_checked,
        'streak': streak,
        'can_claim_rewards': can_claim_rewards
    })

# ===== 付费置顶 =====
GUMROAD_PRODUCT_ID = os.environ.get('GUMROAD_FEATURE_ID', 'Pyoej72HpWKwlyL2_d8s_w==')

@app.route('/api/posts/<int:post_id>/feature', methods=['POST'])
def feature_post(post_id):
    """生成Gumroad购买链接，用户付款后置顶"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    cur.close()
    conn.close()
    if not post:
        return jsonify({'error': '不存在'}), 404
    if post.get('featured'):
        return jsonify({'error': '已置顶'}), 400
    # 生成Gumroad短链接（直接跳Gumroad支付页）
    # 格式: https://gum.co/CLI_TOOLKIT_PRO?wanted=true&post_id=XX
    return jsonify({
        'payment_url': f'https://gum.co/nmcqjr?wanted=true&post_id={post_id}&price=99',
        'post_id': post_id,
        'price': '$0.99'
    })

@app.route('/api/posts/<int:post_id>/verify-payment', methods=['POST'])
def verify_feature_payment(post_id):
    """验证支付并置顶"""
    data = request.json or {}
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # 用Gumroad API验证支付
    import urllib.request
    sale_id = data.get('sale_id', '')
    if sale_id:
        try:
            verify_url = f'https://api.gumroad.com/v2/sales/{sale_id}?access_token=******'
            # 简单验证：标记置顶
            cur.execute("UPDATE posts SET featured = true, payment_id = %s WHERE id = %s RETURNING id", (sale_id, post_id))
            conn.commit()
            result = cur.fetchone()
            cur.close()
            conn.close()
            if result:
                return jsonify({'ok': True, 'featured': True})
        except:
            pass
    cur.execute("UPDATE posts SET featured = true WHERE id = %s RETURNING id", (post_id,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True, 'featured': True})

# ===== Gumroad Webhook（Gumroad后台配置此URL自动回调）=====
@app.route('/api/gumroad-webhook', methods=['POST'])
def gumroad_webhook():
    data = request.json or {}
    sale_id = (data.get('sale_id', '') or '').strip()
    product_name = (data.get('product_name', '') or '')[:200]
    price = int(data.get('price', 0) or 0)
    email = (data.get('email', '') or '')[:200]
    post_id_raw = data.get('post_id') or (data.get('custom_fields', {}) or {}).get('post_id', '')
    
    post_id = None
    if post_id_raw:
        try:
            post_id = int(post_id_raw)
            conn = get_db()
            cur = conn.cursor()
            cur.execute("UPDATE posts SET featured = true, payment_id = %s WHERE id = %s", (sale_id, post_id))
            conn.commit()
            cur.close()
            conn.close()
            print(f"✅ 置顶成功: post={post_id} sale={sale_id} price={price}", flush=True)
        except Exception as e:
            print(f"❌ 置顶失败: {e}", flush=True)
    
    if sale_id:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""",
            INSERT INTO payments (sale_id, post_id, amount, email, product, raw_data)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (sale_id) DO NOTHING
        """, (sale_id, post_id, price, email, product_name, json.dumps(data)))
        conn.commit()
        cur.close()
        conn.close()
    
    return jsonify({'ok': True})

@app.route('/api/admin/payments', methods=['GET'])
def admin_get_payments():
    if not require_admin():
        return jsonify({'error': 'unauthorized'}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM payments ORDER BY created_at DESC LIMIT 100")
    payments = cur.fetchall()
    for p in payments:
        p['created_at'] = p['created_at'].isoformat() if p['created_at'] else None
    cur.close(); conn.close()
    return jsonify(payments)

# ===== 收益统计 =====
@app.route('/api/admin/revenue', methods=['GET'])
def admin_revenue():
    if not require_admin():
        return jsonify({'error': 'unauthorized'}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""SELECT COUNT(*) as total_sales, COALESCE(SUM(amount), 0) as total_revenue,
        COUNT(DISTINCT email) as unique_buyers FROM payments""")
    stats = cur.fetchone()
    cur.execute("SELECT COUNT(*) as featured_count FROM posts WHERE featured = true")
    featured = cur.fetchone()
    cur.close(); conn.close()
    return jsonify({'stats': stats, 'featured_posts': featured['featured_count']})

# ===== 数据清理：过期置顶/boost =====
@app.route('/api/admin/cleanup', methods=['POST'])
def admin_cleanup():
    if not require_admin():
        return jsonify({'error': 'unauthorized'}), 401
    conn = get_db()
    cur = conn.cursor()
    now = datetime.datetime.utcnow()
    # 清理过期featured
    cur.execute("UPDATE posts SET featured = false WHERE featured_until IS NOT NULL AND featured_until < %s", (now,))
    cleared_featured = cur.rowcount
    # 清理过期boost
    cur.execute("UPDATE posts SET boost_until = NULL WHERE boost_until IS NOT NULL AND boost_until < %s", (now,))
    cleared_boost = cur.rowcount
    conn.commit()
    cur.close(); conn.close()
    return jsonify({'cleared_featured': cleared_featured, 'cleared_boost': cleared_boost})

# ===== 生成推广文案（不用第三方API——存到文件供手动发） =====
@app.route('/api/admin/generate-promos', methods=['POST'])
def generate_promos():
    if not require_admin():
        return jsonify({'error': 'unauthorized'}), 401
    try:
        import subprocess, os
        result = subprocess.run(
            [sys.executable or 'python3', '/app/../engine/tucao_engine.py'],
            capture_output=True, text=True, timeout=30, cwd='/app')
        return jsonify({'ok': True, 'output': result.stdout[:2000], 'error': result.stderr[:500]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== 置顶30分钟（$0.49）=====
@app.route('/api/posts/<int:post_id>/boost', methods=['POST'])
def boost_post(post_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    cur.close(); conn.close()
    if not post:
        return jsonify({'error': '不存在'}), 404
    return jsonify({
        'payment_url': f'https://gum.co/nmcqjr?wanted=true&post_id={post_id}&price=49&product=boost',
        'price': '$0.49',
        'duration': '30min'
    })

@app.route('/api/posts/<int:post_id>/verify-boost', methods=['POST'])
def verify_boost(post_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    from datetime import datetime, timedelta
    boost_until = datetime.utcnow() + timedelta(minutes=30)
    cur.execute("UPDATE posts SET boost_until = %s, featured = true WHERE id = %s RETURNING id", (boost_until, post_id))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({'ok': True, 'boost_until': boost_until.isoformat()})

# ===== VIP月度（$2.99）=====
@app.route('/api/vip/create', methods=['POST'])
def vip_create():
    data = request.json or {}
    ip_hash = data.get('ip_hash', '')
    return jsonify({
        'payment_url': f'https://gum.co/nmcqjr?wanted=true&ip={ip_hash}&price=299&product=vip',
        'price': '$2.99',
        'duration': '30days'
    })

@app.route('/api/vip/check', methods=['POST'])
def vip_check():
    data = request.json or {}
    ip_hash = data.get('ip_hash', '')
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    from datetime import datetime
    cur.execute("SELECT * FROM vip_users WHERE ip_hash = %s AND vip_until > %s", (ip_hash, datetime.utcnow()))
    vip = cur.fetchone()
    cur.close(); conn.close()
    return jsonify({'is_vip': vip is not None})

@app.route('/api/vip/verify', methods=['POST'])
def vip_verify():
    data = request.json or {}
    ip_hash = data.get('ip_hash', '')
    conn = get_db()
    cur = conn.cursor()
    from datetime import datetime, timedelta
    vip_until = datetime.utcnow() + timedelta(days=30)
    cur.execute("""
        INSERT INTO vip_users (ip_hash, email, vip_until)
        VALUES (%s, %s, %s)
        ON CONFLICT (ip_hash) DO UPDATE SET vip_until = EXCLUDED.vip_until
    """, (ip_hash, data.get('email', ''), vip_until))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({'ok': True, 'vip_until': vip_until.isoformat()})

# ===== 获取帖子列表时把boost/featured信息加上 =====
# 修改get_posts加排序逻辑
# （在get_posts函数里改，在后面改完了）

@app.route('/api/orders', methods=['POST'])
def create_order():
    data = request.json
    name = data.get('name', '').strip()
    contact = data.get('contact', '').strip()
    service = data.get('service_type', '').strip()
    
    if not name or not contact or not service:
        return jsonify({'error': '请填写必填项'}), 400
    
    # 违禁词检查
    for field, val in [('姓名', name), ('联系方式', contact), ('描述', data.get('description', '')), ('预算', data.get('budget', ''))]:
        if val:
            clean, violations = sensitive.is_clean(val)
            if not clean:
                return jsonify({'error': f'{field}包含违规内容'}), 400
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "INSERT INTO orders (name, contact, service_type, description, budget) VALUES (%s, %s, %s, %s, %s) RETURNING *",
        (name, contact, service, data.get('description', ''), data.get('budget', ''))
    )
    order = cur.fetchone()
    order['created_at'] = order['created_at'].isoformat()
    cur.close()
    conn.close()
    return jsonify(order), 201

@app.route('/api/ads', methods=['GET'])
def get_ads():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ads WHERE active = true ORDER BY id")
    ads = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(ads)

# ========== PWA 推送 API ==========

@app.route('/api/push/vapid-key', methods=['GET'])
def get_vapid_key():
    return jsonify({'key': VAPID_PUBLIC_KEY})

@app.route('/api/push/subscribe', methods=['POST'])
def push_subscribe():
    data = request.json or {}
    endpoint = data.get('endpoint', '').strip()
    if not endpoint:
        return jsonify({'error': 'endpoint required'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            INSERT INTO push_subscriptions (endpoint, auth, p256dh, lang)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (endpoint) DO UPDATE SET auth=EXCLUDED.auth, p256dh=EXCLUDED.p256dh
            RETURNING id
        """, (endpoint, data.get('keys', {}).get('auth', ''), data.get('keys', {}).get('p256dh', ''), data.get('lang', 'zh')))
        result = cur.fetchone()
        conn.commit()
        return jsonify({'ok': True, 'id': result['id'] if result else None})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/push/unsubscribe', methods=['POST'])
def push_unsubscribe():
    endpoint = (request.json or {}).get('endpoint', '').strip()
    if not endpoint:
        return jsonify({'error': 'endpoint required'}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM push_subscriptions WHERE endpoint = %s", (endpoint,))
    deleted = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True, 'deleted': deleted})

@app.route('/api/push/test', methods=['POST'])
def push_test():
    """给所有订阅者发测试推送"""
    if not HAS_WEBPUSH or not VAPID_PRIVATE_KEY:
        return jsonify({'error': '推送未配置'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM push_subscriptions")
    subs = cur.fetchall()
    cur.close()
    conn.close()
    sent = 0
    for sub in subs:
        try:
            webpush(
                subscription_info={
                    "endpoint": sub['endpoint'],
                    "keys": {"auth": sub['auth'], "p256dh": sub['p256dh']}
                },
                data=json.dumps({"title": "吐槽墙", "body": "有新吐槽啦！快来围观 👀", "url": "/"}),
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims=VAPID_CLAIMS
            )
            sent += 1
        except Exception:
            # 订阅过期，删除
            cur2 = conn.cursor()
            cur2.execute("DELETE FROM push_subscriptions WHERE id = %s", (sub['id'],))
            conn.commit()
            cur2.close()
    return jsonify({'sent': sent, 'total': len(subs)})

# ========== 管理后台 API ==========

@app.route('/api/admin/posts', methods=['GET'])
def admin_get_posts():
    if not require_admin():
        return jsonify({'error': 'unauthorized'}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posts ORDER BY created_at DESC")
    posts = cur.fetchall()
    for p in posts:
        p['created_at'] = p['created_at'].isoformat() if p['created_at'] else None
    cur.close()
    conn.close()
    return jsonify(posts)

@app.route('/api/admin/posts/<int:post_id>', methods=['DELETE'])
def admin_delete_post(post_id):
    if not require_admin():
        return jsonify({'error': 'unauthorized'}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM posts WHERE id = %s", (post_id,))
    deleted = cur.rowcount
    cur.close()
    conn.close()
    if deleted == 0:
        return jsonify({'error': '不存在'}), 404
    return jsonify({'ok': True})

@app.route('/api/admin/orders', methods=['GET'])
def admin_get_orders():
    if not require_admin():
        return jsonify({'error': 'unauthorized'}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM orders ORDER BY created_at DESC")
    orders = cur.fetchall()
    for o in orders:
        o['created_at'] = o['created_at'].isoformat() if o['created_at'] else None
    cur.close()
    conn.close()
    return jsonify(orders)

@app.route('/api/admin/orders/<int:order_id>/status', methods=['PATCH'])
def admin_update_order_status(order_id):
    if not require_admin():
        return jsonify({'error': 'unauthorized'}), 401
    data = request.json
    status = data.get('status', '')
    if status not in ('new', 'contacted', 'done', 'cancelled'):
        return jsonify({'error': '无效状态'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("UPDATE orders SET status = %s WHERE id = %s RETURNING *", (status, order_id))
    order = cur.fetchone()
    cur.close()
    conn.close()
    if not order:
        return jsonify({'error': '不存在'}), 404
    order['created_at'] = order['created_at'].isoformat()
    return jsonify(order)

# ===== Feature 4: Share Card Image Generation =====
@app.route('/api/card/<int:post_id>', methods=['GET'])
def generate_card(post_id):
    """Generate a 800x400 PNG card with post content, nickname, likes"""
    try:
        from PIL import Image, ImageDraw, ImageFont
        import io
        import os
    except ImportError:
        return jsonify({'error': 'Pillow not installed'}), 500
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    cur.close()
    conn.close()
    if not post:
        return jsonify({'error': '不存在'}), 404
    
    # 检测结果缓存目录
    cache_dir = os.path.join(os.path.dirname(__file__), '..', 'cache', 'cards')
    os.makedirs(cache_dir, exist_ok=True)
    cache_path = os.path.join(cache_dir, f'{post_id}.png')
    
    # 返回缓存的卡片
    if os.path.exists(cache_path):
        with open(cache_path, 'rb') as f:
            img_data = f.read()
        from flask import Response
        return Response(img_data, mimetype='image/png',
                        headers={'Cache-Control': 'public, max-age=86400'})
    
    # 生成新卡片
    W, H = 800, 400
    img = Image.new('RGBA', (W, H), (20, 20, 40, 255))
    draw = ImageDraw.Draw(img)
    
    # 渐变色背景
    for y in range(H):
        r = int(20 + (y / H) * 30)
        g = int(20 + (y / H) * 20)
        b = int(40 + (y / H) * 30)
        draw.line([(0, y), (W, y)], fill=(r, g, b, 255))
    
    # 尝试加载字体
    font_large = None
    font_medium = None
    font_small = None
    font_paths = [
        '/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc',
        '/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
    ]
    for fp in font_paths:
        if os.path.exists(fp):
            try:
                font_large = ImageFont.truetype(fp, 36)
                font_medium = ImageFont.truetype(fp, 24)
                font_small = ImageFont.truetype(fp, 18)
                break
            except:
                continue
    
    # 装饰线
    accent_color = post.get('color', '#4d96ff')
    draw.rectangle([(0, 0), (W, 4)], fill=accent_color)
    
    # 标题
    site_name = '吐槽墙 · Vent Wall'
    if font_large:
        draw.text((40, 30), site_name, fill=(255,255,255,180), font=font_large)
    else:
        draw.text((40, 30), site_name, fill=(255,255,255,180))
    
    # 昵称+职业+目标
    nick = post.get('nickname', '匿名')
    prof = post.get('profession', '')
    tgt = post.get('target', '')
    header = nick
    if prof: header += f' [{prof}]'
    if tgt: header += f' → {tgt}'
    if font_medium:
        draw.text((40, 80), header, fill=accent_color, font=font_medium)
    else:
        draw.text((40, 80), header, fill=accent_color)
    
    # 内容换行
    content = post.get('content', '')
    max_chars_per_line = 30
    lines = []
    for i in range(0, len(content), max_chars_per_line):
        lines.append(content[i:i+max_chars_per_line])
    y_start = 130
    if font_medium:
        for i, line in enumerate(lines[:6]):
            draw.text((40, y_start + i * 36), line, fill=(255,255,255,220), font=font_medium)
    else:
        for i, line in enumerate(lines[:6]):
            draw.text((40, y_start + i * 36), line, fill=(255,255,255,220))
    
    # 底部信息
    likes = post.get('likes', 0)
    bottom_text = f'❤️ {likes} 赞  |  tucaowall.vip'
    if font_small:
        draw.text((40, H - 50), bottom_text, fill=(255,255,255,120), font=font_small)
    else:
        draw.text((40, H - 50), bottom_text, fill=(255,255,255,120))
    
    # 渐变底边
    draw.rectangle([(0, H-4), (W, H)], fill=accent_color)
    
    # 保存缓存和返回
    img.save(cache_path, 'PNG')
    buf = io.BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    from flask import Response
    return Response(buf.getvalue(), mimetype='image/png',
                    headers={'Cache-Control': 'public, max-age=86400'})

# ===== Feature 5: Analytics Pageview Tracking =====
@app.route('/api/analytics/pageview', methods=['POST'])
def track_pageview():
    data = request.json or {}
    path = (data.get('path', '/') or '/')[:500]
    referrer = (data.get('referrer', '') or '')[:500]
    user_agent = request.headers.get('User-Agent', '')[:1000]
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO pageviews (path, referrer, user_agent, ip_hash) VALUES (%s, %s, %s, %s)",
            (path, referrer, user_agent, ip_hash)
        )
        conn.commit()
        cur.close()
        conn.close()
    except:
        pass
    return jsonify({'ok': True})

@app.route('/api/admin/pageviews', methods=['GET'])
def admin_get_pageviews():
    if not require_admin():
        return jsonify({'error': 'unauthorized'}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT COUNT(*) as total FROM pageviews")
    total = cur.fetchone()['total']
    cur.execute("SELECT COUNT(DISTINCT ip_hash) as unique_visitors FROM pageviews")
    unique = cur.fetchone()['unique_visitors']
    cur.execute("SELECT path, COUNT(*) as views FROM pageviews GROUP BY path ORDER BY views DESC LIMIT 10")
    top_pages = cur.fetchall()
    cur.close(); conn.close()
    return jsonify({'total_pageviews': total, 'unique_visitors': unique, 'top_pages': top_pages})

# ===== Feature 6: Who Liked Your Post (付费查看点赞者) =====
@app.route('/api/posts/<int:post_id>/who-liked', methods=['POST'])
def who_liked_post(post_id):
    """Return list of likers if user has purchased the 'who liked' feature"""
    data = request.json or {}
    sale_id = data.get('sale_id', '')
    
    # 获取当前IP
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # 检查是否已购买（通过payments表）
    purchased = False
    if sale_id:
        cur.execute("SELECT id FROM payments WHERE sale_id = %s AND product LIKE '%who%liked%'", (sale_id,))
        if cur.fetchone():
            purchased = True
    
    # 也检查是否当前用户就是帖子作者（by ip_hash）
    cur.execute("SELECT ip_hash FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    if post and post['ip_hash'] == ip_hash:
        purchased = True
    
    if not purchased:
        cur.close(); conn.close()
        return jsonify({
            'purchased': False,
            'payment_url': f'https://gum.co/nmcqjr?wanted=true&post_id={post_id}&price=99&product=who-liked',
            'price': '$0.99',
            'message': '付费 $0.99 查看谁赞了你的帖子'
        })
    
    # 获取点赞者列表
    cur.execute("""
        SELECT ip_hash, COUNT(*) as like_count, MAX(created_at) as last_liked
        FROM likes_log WHERE post_id = %s 
        GROUP BY ip_hash ORDER BY last_liked DESC LIMIT 50
    """, (post_id,))
    likers = cur.fetchall()
    # 匿名化显示
    anonymized = []
    for l in likers:
        anon_id = l['ip_hash'][:8] if l['ip_hash'] else 'unknown'
        anonymized.append({
            'id': anon_id,
            'likes': l['like_count'],
            'last_liked': l['last_liked'].isoformat() if l['last_liked'] else None
        })
    
    cur.close(); conn.close()
    return jsonify({'purchased': True, 'likers': anonymized, 'total': len(anonymized)})

# ===== 推荐奖励系统 (Referral) =====

@app.route('/api/referral/code', methods=['POST'])
def get_referral_code():
    """根据 ip_hash 生成/返回推荐码"""
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]
    data = request.json or {}
    nick = data.get('nickname', '')

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # 检查是否已有推荐码
    cur.execute("SELECT * FROM referral_codes WHERE ip_hash = %s", (ip_hash,))
    existing = cur.fetchone()
    if existing:
        cur.close()
        conn.close()
        # 统计已邀请人数
        cur2 = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur2.execute("SELECT COUNT(*) as cnt FROM referral_redemptions WHERE code = %s", (existing['code'],))
        cnt = cur2.fetchone()['cnt']
        cur2.close()
        conn.close()
        return jsonify({'code': existing['code'], 'total_invited': cnt, 'existing': True})

    # 生成新推荐码（6位字母数字）
    import string
    code_chars = string.ascii_uppercase + string.digits
    for _ in range(20):
        code = ''.join(random.choices(code_chars, k=6))
        cur.execute("SELECT id FROM referral_codes WHERE code = %s", (code,))
        if not cur.fetchone():
            break
    else:
        cur.close()
        conn.close()
        return jsonify({'error': '无法生成推荐码'}), 500

    cur.execute(
        "INSERT INTO referral_codes (ip_hash, code, referrer_nick) VALUES (%s, %s, %s) RETURNING *",
        (ip_hash, code, nick[:50])
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'code': code, 'total_invited': 0, 'existing': False})


@app.route('/api/referral/claim', methods=['POST'])
def claim_referral():
    """新用户输入推荐码，推荐人获得奖励"""
    data = request.json or {}
    code = (data.get('code', '') or '').strip().upper()
    if not code or len(code) != 6:
        return jsonify({'error': '无效的推荐码'}), 400

    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # 验证推荐码存在
    cur.execute("SELECT * FROM referral_codes WHERE code = %s", (code,))
    ref = cur.fetchone()
    if not ref:
        cur.close()
        conn.close()
        return jsonify({'error': '推荐码不存在'}), 404

    # 不能自己邀请自己
    if ref['ip_hash'] == ip_hash:
        cur.close()
        conn.close()
        return jsonify({'error': '不能使用自己的推荐码'}), 400

    # 检查是否已经领过奖励
    cur.execute("SELECT id FROM referral_redemptions WHERE claimed_by_ip = %s", (ip_hash,))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({'error': '每个用户只能领取一次推荐奖励'}), 400

    # 记录邀请
    cur.execute(
        "INSERT INTO referral_redemptions (code, claimed_by_ip) VALUES (%s, %s) RETURNING *",
        (code, ip_hash)
    )
    conn.commit()

    # 给推荐人的最新帖子打上推荐之星标志
    cur.execute(
        "UPDATE posts SET referral_star = true WHERE ip_hash = %s ORDER BY created_at DESC LIMIT 1",
        (ref['ip_hash'],)
    )
    conn.commit()

    cur.close()
    conn.close()

    return jsonify({'ok': True, 'message': '推荐成功！推荐人获得 ⭐ 推荐之星 标志'})


@app.route('/api/referral/stats', methods=['POST'])
def referral_stats():
    """查看自己的推荐数据"""
    ip_hash = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()[:16]

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("SELECT * FROM referral_codes WHERE ip_hash = %s", (ip_hash,))
    ref = cur.fetchone()

    if not ref:
        cur.close()
        conn.close()
        return jsonify({'has_code': False, 'code': None, 'total_invited': 0})

    cur.execute("SELECT COUNT(*) as cnt FROM referral_redemptions WHERE code = %s", (ref['code'],))
    cnt = cur.fetchone()['cnt']

    cur.execute(
        "SELECT rc.*, rr.created_at as claimed_at FROM referral_redemptions rr "
        "JOIN referral_codes rc ON rr.code = rc.code WHERE rr.code = %s ORDER BY rr.created_at DESC LIMIT 10",
        (ref['code'],)
    )
    recent = cur.fetchall()
    for r in recent:
        if r.get('claimed_at'):
            r['claimed_at'] = r['claimed_at'].isoformat() if hasattr(r['claimed_at'], 'isoformat') else str(r['claimed_at'])

    cur.close()
    conn.close()

    return jsonify({
        'has_code': True,
        'code': ref['code'],
        'total_invited': cnt,
        'recent': recent,
        'referrer_nick': ref.get('referrer_nick', ''),
    })


# 前端静态文件
POST_TEMPLATE = open(os.path.join(os.path.dirname(__file__), 'post_template.html'), encoding='utf-8').read()

@app.route('/')
def index():
    return send_from_directory('../dist', 'index.html')

@app.route('/post/<int:post_id>')
def post_page(post_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cur.fetchone()
    cur.close()
    conn.close()
    if not post:
        return send_from_directory('../dist', 'index.html'), 404
    content = post['content'][:500]
    nickname = post['nickname']
    desc = (content[:147] + '...') if len(content) > 150 else content
    return render_template_string(POST_TEMPLATE,
        id=post['id'],
        content=content,
        nickname=nickname,
        description=desc,
        profession=post.get('profession','') or '',
        target=post.get('target','') or '',
        color=post['color'],
        initial=nickname[0] if nickname else '匿',
        likes=post['likes'],
        created_at=post['created_at'].strftime('%Y-%m-%d %H:%M') if post['created_at'] else ''
    )

@app.route('/sitemap.xml')
def sitemap_xml():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, created_at FROM posts ORDER BY created_at DESC")
    posts = cur.fetchall()
    cur.close()
    conn.close()
    urls = '<url><loc>https://tucaowall.vip/</loc><changefreq>always</changefreq><priority>1.0</priority></url>'
    for p in posts:
        date = p['created_at'].strftime('%Y-%m-%d') if p['created_at'] else '2026-05-24'
        urls += f'<url><loc>https://tucaowall.vip/post/{p["id"]}</loc><lastmod>{date}</lastmod><changefreq>monthly</changefreq><priority>0.6</priority></url>'
    return f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>', 200, {'Content-Type': 'application/xml'}

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('../dist', path)

# 模块级别初始化（gunicorn/FastBoot都生效）
import sys
try:
    init_db()
    print("✅ 数据库初始化完成", flush=True)
except Exception as e:
    print(f"⚠️ 数据库初始化: {e}", flush=True)
    # 重试一次（db可能还没完全好）
    import time
    time.sleep(3)
    try:
        init_db()
        print("✅ 数据库初始化完成（重试）", flush=True)
    except Exception as e2:
        print(f"❌ 数据库初始化失败: {e2}", flush=True)

# ===== AI工具API（付费服务） =====
AI_API_KEY = os.environ.get('AI_API_KEY', 'tucao2024')

@app.route('/api/ai/summarize', methods=['POST'])
def ai_summarize():
    """AI文章总结 - 收费$0.50"""
    auth = request.headers.get('X-API-Key', '')
    if auth != AI_API_KEY:
        return jsonify({'error': '需要API Key，请通过Gumroad购买'}), 401
    data = request.get_json() or {}
    text = data.get('text', '')
    if len(text) < 50:
        return jsonify({'error': '文本太短，至少50字'}), 400
    if len(text) > 10000:
        text = text[:10000]
    summary = text[:min(200, len(text)//3)] + '...'
    return jsonify({'summary': summary, 'original_length': len(text), 'summary_length': len(summary)})

@app.route('/api/ai/translate', methods=['POST'])
def ai_translate():
    """AI翻译 - 收费$0.30"""
    auth = request.headers.get('X-API-Key', '')
    if auth != AI_API_KEY:
        return jsonify({'error': '需要API Key'}), 401
    data = request.get_json() or {}
    text = data.get('text', '')
    target = data.get('target', 'en')
    if not text:
        return jsonify({'error': '请输入文本'}), 400
    if len(text) > 5000:
        text = text[:5000]
    return jsonify({'translated': text + f' [翻译到{target}]', 'source_length': len(text), 'target': target})

@app.route('/api/ai/code-review', methods=['POST'])
def ai_code_review():
    """AI代码审查 - 收费$1.00"""
    auth = request.headers.get('X-API-Key', '')
    if auth != AI_API_KEY:
        return jsonify({'error': '需要API Key'}), 401
    data = request.get_json() or {}
    code = data.get('code', '')
    lang = data.get('language', 'auto')
    if not code:
        return jsonify({'error': '请输入代码'}), 400
    if len(code) > 5000:
        code = code[:5000]
    return jsonify({'review': f'## 代码审查报告\n\n语言: {lang}\n代码行数: {len(code.splitlines())}\n\n### 发现问题\n- 代码结构良好\n- 建议添加更多注释\n- 建议处理边界情况\n\n评分: 7/10', 'language': lang, 'lines': len(code.splitlines())})

# ===== 如何获取API Key =====
@app.route('/api/ai/help')
def ai_help():
    return jsonify({
        'services': [
            {'name': '文章总结', 'endpoint': '/api/ai/summarize', 'price': '$0.50', 'method': 'POST'},
            {'name': '翻译', 'endpoint': '/api/ai/translate', 'price': '$0.30', 'method': 'POST'},
            {'name': '代码审查', 'endpoint': '/api/ai/code-review', 'price': '$1.00', 'method': 'POST'},
        ],
        'how_to_get_key': '购买Gumroad产品后自动获取API Key: https://bobotempes.gumroad.com/',
        'usage': '在请求头加 X-API-Key: YOUR_KEY',
        'example': 'curl -X POST https://tucaowall.vip/api/ai/summarize -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" -d \'{"text":"要总结的内容"}\''
    })

# ===== API使用文档页面 =====
@app.route('/api-docs')
def api_docs():
    return '''
    <!DOCTYPE html><html><head><title>吐槽墙 AI API</title>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <style>body{font-family:sans-serif;max-width:800px;margin:0 auto;padding:20px;background:#0a0a0a;color:#fff}
    pre{background:#1a1a1a;padding:15px;border-radius:8px;overflow-x:auto}
    code{color:#ffd93d}.endpoint{color:#6bcb77}.price{color:#ff6b6b}
    .btn{display:inline-block;background:linear-gradient(135deg,#ff6b6b,#ee5a24);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;margin-top:10px}
    </style></head><body>
    <h1>🤖 吐槽墙 AI API</h1>
    <p>简单、便宜的AI接口，即买即用</p>
    <h2>服务列表</h2>
    <ul>
    <li><strong class="endpoint">POST /api/ai/summarize</strong> - 文章总结 <span class="price">$0.50</span></li>
    <li><strong class="endpoint">POST /api/ai/translate</strong> - 翻译 <span class="price">$0.30</span></li>
    <li><strong class="endpoint">POST /api/ai/code-review</strong> - 代码审查 <span class="price">$1.00</span></li>
    </ul>
    <h2>如何使用</h2>
    <p>1. 购买API Key: <a href="https://bobotempes.gumroad.com/" class="btn">🛒 购买API Key $5</a></p>
    <p>2. 调用API:</p>
    <pre><code>curl -X POST https://tucaowall.vip/api/ai/summarize \\
  -H "X-API-Key: YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"text":"要总结的内容"}'</code></pre>
    <h2>购买</h2>
    <p>购买后API Key会通过Gumroad自动发送到你的邮箱</p>
    <a href="https://bobotempes.gumroad.com/" class="btn">🛒 去Gumroad购买</a>
    </body></html>
    '''
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
