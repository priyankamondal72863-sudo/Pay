import os, io, json, secrets
from datetime import timedelta
from fastapi import FastAPI, Request, Depends, HTTPException, Form, Header
from fastapi.responses import RedirectResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import select, func
from sqlalchemy.orm import Session
import segno
from db import Base, engine, SessionLocal, get_db
from models import User, GatewayCred, ApiKey, Txn, AuditLog, Subscription, LoginLog, now
import security as sec
import providers as gw

app = FastAPI(title="Zyvo Gateway")
app.add_middleware(SessionMiddleware, secret_key=sec.SECRET, https_only=bool(os.getenv("RENDER")), same_site="lax", max_age=86400 * 7)
_HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIRS = [os.path.join(_HERE, "templates"), _HERE]  # works with a templates/ folder OR html files placed next to main.py
_NEED = ["base", "home", "login", "register", "dashboard", "transactions", "gateways", "keys", "docs", "checkout", "admin", "forgot", "reset", "webhooks", "settings", "subscription", "receipt", "admin_subs", "team"]
_missing = [n + ".html" for n in _NEED if not any(os.path.exists(os.path.join(d, n + ".html")) for d in TEMPLATE_DIRS)]
if _missing: raise ImportError("Missing template files (upload them to GitHub): " + ", ".join(_missing))
templates = Jinja2Templates(directory=TEMPLATE_DIRS)
templates.env.filters["rs"] = lambda p: f"₹{(p or 0)/100:,.2f}"

def _startup_inner():
    Base.metadata.create_all(engine)
    em, pw = os.getenv("ADMIN_EMAIL"), os.getenv("ADMIN_PASSWORD")
    if em and pw:
        with SessionLocal() as db:
            if not db.scalar(select(User).where(User.email == em.lower())):
                db.add(User(name="Owner", username="owner", email=em.lower(), phone="", pw_hash=sec.hash_pw(pw), role="owner")); db.commit()
    from extras import start
    start()

# ---------- helpers ----------
def base_url(request): return os.getenv("RENDER_EXTERNAL_URL") or str(request.base_url).rstrip("/")
def render(request, name, user=None, **ctx):
    s = request.session
    if "csrf" not in s: s["csrf"] = secrets.token_hex(16)
    ctx.update(user=user, csrf=s["csrf"], flash=s.pop("flash", None), base=base_url(request))
    return templates.TemplateResponse(request, name, ctx)
def flash(request, msg, kind="ok"): request.session["flash"] = {"m": msg, "k": kind}
def go(url): return RedirectResponse(url, status_code=303)
def check_csrf(request, token):
    if not token or not secrets.compare_digest(token, request.session.get("csrf", "")): raise HTTPException(400, "Bad CSRF token")
def audit(db, uid, action, detail=""): db.add(AuditLog(user_id=uid, action=action, detail=detail[:300]))
def current(request: Request, db: Session = Depends(get_db)):
    u = db.get(User, request.session.get("uid")) if request.session.get("uid") else None
    if not u or u.status != "active": request.session.clear(); raise HTTPException(303, headers={"Location": "/login"})
    return u
def owner_only(u=Depends(current)):
    if u.role != "owner": raise HTTPException(403, "Owner only")
    return u
def optional_user(request: Request, db: Session = Depends(get_db)):
    uid = request.session.get("uid"); return db.get(User, uid) if uid else None

# ---------- public + auth ----------
@app.get("/")
def home(request: Request, u=Depends(optional_user)): return render(request, "home.html", u)
@app.get("/login")
def login_page(request: Request): return render(request, "login.html")
@app.post("/login")
def login(request: Request, identity: str = Form(), password: str = Form(), csrf: str = Form(""), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else "?"
    if not sec.rate_ok(f"login:{ip}:{identity.lower()}", 5, 300):
        flash(request, "Too many attempts. Try again in 5 minutes.", "err"); return go("/login")
    u = db.scalar(select(User).where((User.email == identity.lower()) | (User.username == identity.lower())))
    if not u or not sec.check_pw(password, u.pw_hash):
        db.add(LoginLog(user_id=u.id if u else None, identity=identity[:120], ip=ip, ok=False)); db.commit()
        flash(request, "Invalid credentials.", "err"); return go("/login")
    db.add(LoginLog(user_id=u.id, identity=identity[:120], ip=ip, ok=True))
    if u.status != "active": flash(request, "Account suspended.", "err"); return go("/login")
    request.session.clear(); request.session["uid"] = u.id; audit(db, u.id, "login", ip); db.commit()
    return go("/admin" if u.role == "owner" else "/dashboard")
@app.get("/register")
def register_page(request: Request): return render(request, "register.html")
@app.post("/register")
def register(request: Request, name: str = Form(), username: str = Form(), email: str = Form(), phone: str = Form(),
             password: str = Form(), confirm: str = Form(), csrf: str = Form(""), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    username, email = username.strip().lower(), email.strip().lower()
    err = None
    if len(password) < 8: err = "Password must be at least 8 characters."
    elif password != confirm: err = "Passwords do not match."
    elif not username.replace("_", "").isalnum() or len(username) < 3: err = "Username: 3+ letters/numbers/underscore."
    elif db.scalar(select(User).where(User.username == username)): err = "Username already taken."
    elif db.scalar(select(User).where(User.email == email)): err = "Email already registered."
    if err: flash(request, err, "err"); return go("/register")
    u = User(name=name.strip(), username=username, email=email, phone=phone.strip(), pw_hash=sec.hash_pw(password)); db.add(u); db.flush()
    audit(db, u.id, "register"); db.commit()
    request.session.clear(); request.session["uid"] = u.id
    return go("/dashboard")
@app.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf); request.session.clear(); return go("/")
@app.get("/docs-api")
def docs(request: Request, u=Depends(optional_user)): return render(request, "docs.html", u)

# ---------- dashboard ----------
@app.get("/dashboard")
def dashboard(request: Request, u=Depends(current), db: Session = Depends(get_db)):
    by = dict(db.execute(select(Txn.status, func.count()).where(Txn.user_id == u.id).group_by(Txn.status)).all())
    total = sum(by.values()); ok = by.get("SUCCESS", 0)
    vol = db.scalar(select(func.coalesce(func.sum(Txn.amount), 0)).where(Txn.user_id == u.id, Txn.status == "SUCCESS"))
    today = now().replace(hour=0, minute=0, second=0, microsecond=0)
    t_all = db.scalar(select(func.count()).where(Txn.user_id == u.id, Txn.created >= today))
    t_ok = db.scalar(select(func.count()).where(Txn.user_id == u.id, Txn.created >= today, Txn.status == "SUCCESS"))
    t_vol = db.scalar(select(func.coalesce(func.sum(Txn.amount), 0)).where(Txn.user_id == u.id, Txn.created >= today, Txn.status == "SUCCESS"))
    gwise = db.execute(select(Txn.gateway, func.count(), func.coalesce(func.sum(Txn.amount), 0)).where(Txn.user_id == u.id, Txn.status == "SUCCESS").group_by(Txn.gateway)).all()
    days = []
    for i in range(6, -1, -1):
        d0 = today - timedelta(days=i); d1 = d0 + timedelta(days=1)
        days.append((d0.strftime("%d %b"), db.scalar(select(func.coalesce(func.sum(Txn.amount), 0)).where(Txn.user_id == u.id, Txn.status == "SUCCESS", Txn.created >= d0, Txn.created < d1))))
    recent = db.scalars(select(Txn).where(Txn.user_id == u.id).order_by(Txn.id.desc()).limit(8)).all()
    s = dict(total=total, ok=ok, failed=by.get("FAILED", 0), pending=by.get("PENDING", 0) + by.get("CREATED", 0), vol=vol, t_all=t_all, t_ok=t_ok, t_vol=t_vol,
             rate=round(ok * 100 / total, 1) if total else 0, avg=int(vol / ok) if ok else 0)
    return render(request, "dashboard.html", u, s=s, gwise=gwise, days=days, maxd=max([d[1] for d in days] + [1]), recent=recent)

@app.get("/transactions")
def transactions(request: Request, status: str = "", gateway: str = "", search: str = "", u=Depends(current), db: Session = Depends(get_db)):
    q = select(Txn).where(Txn.user_id == u.id)
    if status: q = q.where(Txn.status == status)
    if gateway: q = q.where(Txn.gateway == gateway)
    if search: q = q.where(Txn.pay_id.contains(search) | Txn.merchant_order_id.contains(search) | Txn.provider_ref.contains(search))
    return render(request, "transactions.html", u, rows=db.scalars(q.order_by(Txn.id.desc()).limit(200)).all(), f=dict(status=status, gateway=gateway, search=search))

# ---------- gateways ----------
@app.get("/gateways")
def gateways(request: Request, u=Depends(current), db: Session = Depends(get_db)):
    creds = {c.gateway: c for c in db.scalars(select(GatewayCred).where(GatewayCred.user_id == u.id))}
    return render(request, "gateways.html", u, creds=creds, adapters=gw.ADAPTERS)
@app.post("/gateways/paytm/save")
def paytm_save(request: Request, mid: str = Form(), key: str = Form(""), pos_id: str = Form(""), env: str = Form("staging"), csrf: str = Form(""), u=Depends(current), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    if env not in ("staging", "production"): raise HTTPException(400)
    c = db.scalar(select(GatewayCred).where(GatewayCred.user_id == u.id, GatewayCred.gateway == "paytm"))
    old = sec.dec(c.data_enc) if c else {}
    key = key.strip() or old.get("key", "")
    if not key: flash(request, "Merchant Key required.", "err"); return go("/gateways")
    data = sec.enc({"mid": mid.strip(), "key": key, "pos_id": pos_id.strip()})
    if c: c.data_enc, c.env = data, env
    else: db.add(GatewayCred(user_id=u.id, gateway="paytm", data_enc=data, env=env))
    audit(db, u.id, "gateway_save", "paytm"); db.commit(); flash(request, "Paytm credentials saved (encrypted)."); return go("/gateways")
@app.post("/gateways/paytm/{action}")
def paytm_action(action: str, request: Request, csrf: str = Form(""), u=Depends(current), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    c = db.scalar(select(GatewayCred).where(GatewayCred.user_id == u.id, GatewayCred.gateway == "paytm"))
    if not c: flash(request, "Save credentials first.", "err"); return go("/gateways")
    if action == "test":
        try: ok, msg = gw.paytm.test(sec.dec(c.data_enc), c.env)
        except Exception as e: ok, msg = False, str(e)[:250]
        c.last_test_at, c.last_test_ok, c.last_test_msg = now(), ok, msg; flash(request, msg, "ok" if ok else "err")
    elif action in ("enable", "disable"):
        c.enabled = action == "enable"; flash(request, f"Paytm {action}d.")
    db.commit(); return go("/gateways")

# ---------- api keys ----------
@app.get("/keys")
def keys(request: Request, u=Depends(current), db: Session = Depends(get_db)):
    return render(request, "keys.html", u, keys=db.scalars(select(ApiKey).where(ApiKey.user_id == u.id).order_by(ApiKey.id.desc())).all(), newkey=request.session.pop("newkey", None))
@app.post("/keys/create")
def key_create(request: Request, label: str = Form(""), csrf: str = Form(""), u=Depends(current), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    from extras import max_keys
    if db.scalar(select(func.count()).where(ApiKey.user_id == u.id, ApiKey.revoked == False)) >= max_keys(db, u.id):  # noqa
        flash(request, "Key limit reached for your plan.", "err"); return go("/keys")
    k = sec.new_api_key(); db.add(ApiKey(user_id=u.id, label=label[:60], prefix=k[:9], key_hash=sec.hash_key(k)))
    audit(db, u.id, "key_create"); db.commit(); request.session["newkey"] = k; return go("/keys")
@app.post("/keys/{kid}/revoke")
def key_revoke(kid: int, request: Request, csrf: str = Form(""), u=Depends(current), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    k = db.get(ApiKey, kid)
    if k and k.user_id == u.id: k.revoked = True; audit(db, u.id, "key_revoke", str(kid)); db.commit()
    return go("/keys")

# ---------- payment core ----------
def cfg_for(db, user_id, gateway):
    c = db.scalar(select(GatewayCred).where(GatewayCred.user_id == user_id, GatewayCred.gateway == gateway, GatewayCred.enabled == True))  # noqa
    return (sec.dec(c.data_enc), c.env) if c else (None, None)
def create_payment(db, user, amount, gateway, merchant_order_id, customer):
    ad = gw.get(gateway)
    if not ad or not ad.AVAILABLE: raise HTTPException(400, f"Gateway '{gateway}' not available")
    if not (1 <= amount <= 10_000_000): raise HTTPException(400, "Invalid amount")
    if merchant_order_id:
        ex = db.scalar(select(Txn).where(Txn.user_id == user.id, Txn.merchant_order_id == merchant_order_id))
        if ex: return ex
    from extras import check_plan; check_plan(db, user, gateway)
    cfg, env = cfg_for(db, user.id, gateway)
    if not cfg: raise HTTPException(400, f"Gateway '{gateway}' not configured/enabled")
    pay_id = "ORD" + secrets.token_hex(8).upper()
    try: r = ad.create(cfg, env, pay_id, amount)
    except Exception as e: raise HTTPException(502, str(e)[:200])
    t = Txn(pay_id=pay_id, user_id=user.id, merchant_order_id=merchant_order_id, gateway=gateway, amount=amount, status="PENDING",
            customer=json.dumps(customer or {}), qr_data=r["qr_data"], provider_ref=r["provider_ref"], expires_at=now() + timedelta(minutes=10))
    db.add(t); db.commit(); return t
def _refresh(db, t):
    """Only a provider-verified response (order id + amount + success) may set SUCCESS. Idempotent."""
    if t.status not in ("PENDING", "CREATED"): return t
    cfg, env = cfg_for(db, t.user_id, t.gateway)
    if cfg:
        try:
            r = gw.get(t.gateway).status(cfg, env, t.pay_id)
            t = db.scalar(select(Txn).where(Txn.id == t.id).with_for_update().execution_options(populate_existing=True))
            if t.status in ("PENDING", "CREATED"):
                if r["state"] == "SUCCESS":
                    if r["order_id"] == t.pay_id and r["amount"] == t.amount: t.status, t.provider_ref, t.updated = "SUCCESS", r["txn_id"] or t.provider_ref, now()
                    else: audit(db, t.user_id, "verify_mismatch", t.pay_id)
                elif r["state"] == "FAILED": t.status, t.updated = "FAILED", now()
        except Exception as e: audit(db, t.user_id, "verify_error", f"{t.pay_id}: {e}")
    if t.status == "PENDING" and t.expires_at < now(): t.status, t.updated = "EXPIRED", now()
    db.commit(); return t
def refresh(db, t):
    old = t.status; t = _refresh(db, t)
    if t.status != old:
        from extras import on_change; on_change(db, t)
    return t
def tx_json(t, request):
    return {"order_id": t.merchant_order_id or t.pay_id, "pay_id": t.pay_id, "status": t.status, "amount": t.amount / 100, "currency": t.currency,
            "gateway": t.gateway, "transaction_id": t.provider_ref, "payment_url": f"{base_url(request)}/pay/{t.pay_id}"}

# ---------- public API ----------
def api_user(request: Request, authorization: str = Header(""), x_api_key: str = Header(""), api_key: str = "", db: Session = Depends(get_db)):
    k = x_api_key or api_key or authorization.replace("Bearer ", "").strip()
    row = db.scalar(select(ApiKey).where(ApiKey.key_hash == sec.hash_key(k))) if k else None
    if not row or row.revoked: raise HTTPException(401, "Invalid API key")
    if not sec.rate_ok(f"api:{row.id}", 60): raise HTTPException(429, "Rate limit: 60 req/min")
    u = db.get(User, row.user_id)
    if u.status != "active": raise HTTPException(403, "Account suspended")
    row.uses += 1; row.last_used = now(); db.commit(); return u
@app.exception_handler(HTTPException)
async def http_exc(request: Request, exc: HTTPException):
    if exc.status_code == 303: return RedirectResponse(exc.headers["Location"], 303)
    if request.url.path.startswith("/api/"): return JSONResponse({"success": False, "error": exc.detail}, exc.status_code)
    return Response(str(exc.detail), exc.status_code)
@app.post("/api/v1/payment/create")
async def api_create(request: Request, u=Depends(api_user), db: Session = Depends(get_db)):
    b = await request.json()
    try: amt = round(float(b["amount"]) * 100)
    except Exception: raise HTTPException(400, "amount required")
    t = create_payment(db, u, amt, b.get("gateway", "paytm"), (b.get("order_id") or None), b.get("customer"))
    return {"success": True, **tx_json(t, request)}
@app.get("/api/create_order")  # simple GET style: ?amount=99&api_key=...
def api_create_get(request: Request, amount: float, gateway: str = "paytm", order_id: str = "", u=Depends(api_user), db: Session = Depends(get_db)):
    t = create_payment(db, u, round(amount * 100), gateway, order_id or None, None)
    return {"status": "success", "data": {**tx_json(t, request), "qr_url": f"{base_url(request)}/pay/{t.pay_id}/qr.svg", "expires_at": t.expires_at.isoformat() + "Z"}}
def _lookup(db, u, oid):
    t = db.scalar(select(Txn).where(Txn.user_id == u.id, (Txn.pay_id == oid) | (Txn.merchant_order_id == oid)))
    if not t: raise HTTPException(404, "Order not found")
    return t
@app.get("/api/v1/payment/status/{oid}")
def api_status(oid: str, request: Request, u=Depends(api_user), db: Session = Depends(get_db)):
    return {"success": True, **tx_json(refresh(db, _lookup(db, u, oid)), request)}
@app.get("/api/verify")
def api_verify(order_id: str, request: Request, u=Depends(api_user), db: Session = Depends(get_db)):
    t = refresh(db, _lookup(db, u, order_id))
    if t.status != "SUCCESS": return {"status": t.status.lower(), "data": None}
    return {"status": "success", "data": {"order_id": t.pay_id, "amount": t.amount / 100, "utr": t.provider_ref, "payment_time": t.updated.isoformat() + "Z"}}
@app.get("/api/v1/transactions")
def api_txns(request: Request, u=Depends(api_user), db: Session = Depends(get_db)):
    return {"success": True, "data": [tx_json(t, request) for t in db.scalars(select(Txn).where(Txn.user_id == u.id).order_by(Txn.id.desc()).limit(100))]}
@app.get("/api/v1/account")
def api_account(u=Depends(api_user)): return {"success": True, "username": u.username, "email": u.email, "role": u.role}
@app.get("/api/v1/gateways")
def api_gws(u=Depends(api_user), db: Session = Depends(get_db)):
    return {"success": True, "gateways": [{"gateway": k, "available": a.AVAILABLE, "enabled": bool(cfg_for(db, u.id, k)[0])} for k, a in gw.ADAPTERS.items()]}

# ---------- hosted checkout ----------
def _pay(db, pay_id):
    t = db.scalar(select(Txn).where(Txn.pay_id == pay_id))
    if not t: raise HTTPException(404, "Not found")
    return t
@app.get("/pay/{pay_id}")
def pay_page(pay_id: str, request: Request, db: Session = Depends(get_db)):
    t = _pay(db, pay_id); m = db.get(User, t.user_id)
    return render(request, "checkout.html", None, t=t, merchant=m.name, secs=max(0, int((t.expires_at - now()).total_seconds())))
@app.get("/pay/{pay_id}/qr.svg")
def pay_qr(pay_id: str, db: Session = Depends(get_db)):
    t = _pay(db, pay_id); buf = io.BytesIO(); segno.make(t.qr_data, error="m").save(buf, kind="svg", scale=8, border=2)
    return Response(buf.getvalue(), media_type="image/svg+xml")
@app.get("/pay/{pay_id}/status")
def pay_status(pay_id: str, db: Session = Depends(get_db)):
    if not sec.rate_ok(f"poll:{pay_id}", 40): raise HTTPException(429, "slow down")
    t = refresh(db, _pay(db, pay_id)); return {"status": t.status}
@app.api_route("/callback/paytm", methods=["GET", "POST"])
async def paytm_cb(request: Request, db: Session = Depends(get_db)):
    f = dict(await request.form()) if request.method == "POST" else dict(request.query_params)
    t = db.scalar(select(Txn).where(Txn.pay_id == f.get("ORDERID", ""))) # status is re-verified server-to-server; callback body is never trusted
    if t and f.get("CHECKSUMHASH"):
        try:
            cfg, _ = cfg_for(db, t.user_id, "paytm")
            if not (cfg and gw.paytm.verify_signature({k: v for k, v in f.items() if k != "CHECKSUMHASH"}, cfg["key"], f["CHECKSUMHASH"])):
                audit(db, t.user_id, "callback_bad_checksum", t.pay_id); db.commit()
        except Exception: pass
    if t: refresh(db, t); return go(f"/pay/{t.pay_id}")
    return Response("ok")

# ---------- owner ----------
@app.get("/admin")
def admin(request: Request, u=Depends(owner_only), db: Session = Depends(get_db)):
    c = lambda *w: db.scalar(select(func.count()).where(*w)) if w else db.scalar(select(func.count()).select_from(Txn))
    st = dict(users=db.scalar(select(func.count()).select_from(User)), active=c(User.status == "active"), sellers=c(User.role == "seller"), resellers=c(User.role == "reseller"),
              txns=db.scalar(select(func.count()).select_from(Txn)), ok=c(Txn.status == "SUCCESS"), failed=c(Txn.status == "FAILED"),
              vol=db.scalar(select(func.coalesce(func.sum(Txn.amount), 0)).where(Txn.status == "SUCCESS")),
              rev=db.scalar(select(func.coalesce(func.sum(Subscription.price_paid), 0))))
    return render(request, "admin.html", u, st=st, users=db.scalars(select(User).order_by(User.id.desc()).limit(200)).all(),
                  logs=db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(30)).all())
@app.post("/admin/users/{uid}/toggle")
def admin_toggle(uid: int, request: Request, csrf: str = Form(""), u=Depends(owner_only), db: Session = Depends(get_db)):
    check_csrf(request, csrf); t = db.get(User, uid)
    if t and t.role != "owner": t.status = "suspended" if t.status == "active" else "active"; audit(db, u.id, "user_toggle", f"{uid}->{t.status}"); db.commit()
    return go("/admin")

STARTUP_ERROR = None
@app.on_event("startup")
def startup():
    global STARTUP_ERROR
    try: _startup_inner()
    except Exception as e:
        import traceback; print(traceback.format_exc(), flush=True)
        STARTUP_ERROR = f"{type(e).__name__}: {str(e)[:400]}"
@app.middleware("http")
async def show_startup_error(request: Request, call_next):
    if STARTUP_ERROR: return Response("STARTUP ERROR - fix the setting/DB, then redeploy:\n\n" + STARTUP_ERROR, status_code=500, media_type="text/plain")
    return await call_next(request)
@app.get("/healthz")
def healthz(): return {"ok": True}
@app.head("/healthz")
def healthz_head(): return Response(status_code=200)

# ---------- keep-alive (Render free never sleeps): pings its own public URL every 5 min ----------
def _keep_alive():
    import time, requests
    url = (os.getenv("KEEP_ALIVE_URL") or os.getenv("RENDER_EXTERNAL_URL") or "").rstrip("/")
    if not url: return
    time.sleep(45)
    while True:
        try: requests.get(url + "/healthz", timeout=20)
        except Exception: pass
        time.sleep(int(os.getenv("KEEP_ALIVE_INTERVAL", "300")))
import threading as _th
_th.Thread(target=_keep_alive, daemon=True, name="keep-alive").start()

from extras import router  # noqa: E402
app.include_router(router)
