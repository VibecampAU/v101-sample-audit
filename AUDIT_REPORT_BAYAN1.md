# Security, Performance, and Load/Stress Audit Report
**Bayan Events Platform**  
**Date:** January 16, 2026  
**Auditor:** AI Code Review  
**Scope:** Security, Performance, Load/Stress Testing Readiness

---

## Executive Summary

This audit examines the Bayan Events Platform codebase for security vulnerabilities, performance bottlenecks, and scalability concerns. The application is a FastAPI-based event management system for Filipino-Australian communities, deployed on Fly.io with SQLite.

**Overall Risk Level:** 🟡 **MEDIUM**

The application demonstrates good security practices in authentication and password handling, but has several critical security gaps and performance concerns that should be addressed before production scale.

---

## 🔒 Security Audit

### Critical Security Issues

#### 1. **CORS Configuration - CRITICAL** ⚠️
**Location:** `main.py:47-53`
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ⚠️ SECURITY RISK
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Issue:** CORS allows all origins (`["*"]`) with credentials enabled, creating a significant security vulnerability.

**Risk:** 
- Cross-origin attacks
- Credential theft
- CSRF attacks facilitated

**Recommendation:**
```python
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://bayan.fly.dev").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
```

**Priority:** 🔴 **HIGH** - Fix immediately

---

#### 2. **Missing CSRF Protection** ⚠️
**Location:** All POST endpoints

**Issue:** No CSRF token validation implemented for state-changing operations (event creation, updates, ticket requests, signup).

**Risk:**
- Cross-Site Request Forgery attacks
- Unauthorized actions on behalf of authenticated users

**Recommendation:**
- Implement CSRF tokens using `fastapi-csrf-protect` or similar
- Add CSRF tokens to all forms
- Validate tokens on all POST/PUT/DELETE endpoints

**Priority:** 🔴 **HIGH** - Critical for production

---

#### 3. **Weak Password Policy** ⚠️
**Location:** `app/routes/auth_routes.py:185`

**Issue:** Minimum password length is only 6 characters.

```python
if len(password) < 6:
    return templates.TemplateResponse("signup.html", {
        "error": "Password must be at least 6 characters long",
        ...
    })
```

**Risk:**
- Weak passwords vulnerable to brute force attacks
- No complexity requirements (uppercase, numbers, special chars)

**Recommendation:**
- Increase minimum length to 12 characters
- Add complexity requirements
- Consider password strength meter
- Implement password breach checking (Have I Been Pwned API)

**Priority:** 🟡 **MEDIUM**

---

#### 4. **reCAPTCHA Bypass in Development** ⚠️
**Location:** `app/routes/auth_routes.py:25-27`

**Issue:** If `RECAPTCHA_SECRET_KEY` is not set, verification returns `True`, allowing bypass.

```python
if not recaptcha_secret:
    logger.warning("RECAPTCHA_SECRET_KEY not set, skipping verification")
    return True  # ⚠️ Allows bypass
```

**Risk:**
- In production, if secret key is misconfigured, reCAPTCHA is bypassed
- Bot attacks on signup and ticket request endpoints

**Recommendation:**
- Fail secure: return `False` if secret key not configured
- Add environment validation on startup
- Log security warnings for missing keys

**Priority:** 🟡 **MEDIUM**

---

#### 5. **No Rate Limiting** ⚠️
**Location:** All endpoints

**Issue:** No rate limiting implemented on any endpoints.

**Risk:**
- Brute force attacks on login
- DDoS attacks
- Resource exhaustion
- Spam signups/ticket requests

**Recommendation:**
- Implement rate limiting using `slowapi` or `fastapi-limiter`
- Set limits per IP:
  - Login: 5 attempts per 15 minutes
  - Signup: 3 per hour
  - Ticket requests: 10 per hour
  - General API: 100 requests per minute

**Priority:** 🔴 **HIGH** - Critical for production

---

#### 6. **Missing Security Headers** ⚠️
**Location:** `main.py`

**Issue:** No security headers middleware configured.

**Risk:**
- XSS attacks
- Clickjacking
- MIME type sniffing
- Information disclosure

**Recommendation:**
```python
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
```

**Priority:** 🟡 **MEDIUM**

---

#### 7. **Database Query Logging in Production** ⚠️
**Location:** `app/database.py:27`

**Issue:** `echo=True` enables SQL query logging, which may expose sensitive data.

```python
engine = create_async_engine(DATABASE_URL, echo=True)
```

**Risk:**
- Sensitive data in logs
- Performance overhead
- Log file size growth

**Recommendation:**
```python
import logging
import os

echo = os.getenv("DB_ECHO", "false").lower() == "true"
engine = create_async_engine(DATABASE_URL, echo=echo)
```

**Priority:** 🟢 **LOW**

---

#### 8. **URL Input Validation** ⚠️
**Location:** `app/models/event.py` - `more_info_url` field

**Issue:** No validation that `more_info_url` is a valid URL format or safe protocol.

**Risk:**
- XSS via `javascript:` URLs
- Open redirect vulnerabilities
- Malicious link injection

**Recommendation:**
```python
from pydantic import HttpUrl, validator

class EventCreate(SQLModel):
    more_info_url: Optional[HttpUrl] = None
    
    @validator('more_info_url')
    def validate_url_scheme(cls, v):
        if v and v.scheme not in ['http', 'https']:
            raise ValueError('URL must use http or https')
        return v
```

**Priority:** 🟡 **MEDIUM**

---

#### 9. **Session Expiration Uses UTC** ⚠️
**Location:** `app/controllers/auth_controller.py:78`

**Issue:** Session expiration uses `datetime.utcnow()` instead of timezone-aware datetime.

```python
expires_at = datetime.utcnow() + timedelta(hours=24)
```

**Risk:**
- Timezone confusion
- Inconsistent expiration times

**Recommendation:**
```python
from datetime import datetime, timezone
expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
```

**Priority:** 🟢 **LOW**

---

#### 10. **No Email Validation** ⚠️
**Location:** `app/models/organiser.py` - `email` field

**Issue:** Email field uses basic `str` type without `EmailStr` validation.

**Risk:**
- Invalid email formats accepted
- Potential for email injection

**Recommendation:**
```python
from pydantic import EmailStr

class OrganiserCreate(SQLModel):
    email: EmailStr
```

**Priority:** 🟢 **LOW**

---

### Security Strengths ✅

1. **Password Hashing:** ✅ Uses bcrypt via passlib
2. **Session Tokens:** ✅ Cryptographically secure (`secrets.token_urlsafe(32)`)
3. **SQL Injection Prevention:** ✅ Uses SQLAlchemy ORM (parameterized queries)
4. **XSS Prevention:** ✅ Jinja2 auto-escapes by default
5. **Secure Cookies:** ✅ HttpOnly, Secure (in production), SameSite=Lax
6. **Authentication:** ✅ Proper session-based auth with expiration
7. **Authorization:** ✅ Proper checks for organiser ownership

---

## ⚡ Performance Audit

### Critical Performance Issues

#### 1. **N+1 Query Problem** 🔴
**Location:** `app/controllers/event_controller.py:128-132`

**Issue:** `get_upcoming_events()` calls `get_event_by_id()` for each event, causing N+1 queries.

```python
events_response = []
for event in events:
    event_response = await self.get_event_by_id(event.id)  # ⚠️ N+1 queries
    if event_response:
        events_response.append(event_response)
```

**Impact:** 
- For 100 events: 1 query + 100 queries = 101 database queries
- Significant performance degradation

**Recommendation:**
```python
# Use joinedload or selectinload for eager loading
from sqlalchemy.orm import selectinload

query = select(Event).options(
    selectinload(Event.community),
    selectinload(Event.organiser)
).where(...)
```

**Priority:** 🔴 **HIGH**

---

#### 2. **Inefficient State Counting** 🔴
**Location:** `app/routes/public_routes.py:50-64`

**Issue:** Loads ALL events into memory to count by state.

```python
all_events = await event_controller.get_upcoming_events(state=None)
state_counts[""] = len(all_events)
state_counts["AUS"] = sum(1 for e in all_events if e.state == "AUS")
```

**Impact:**
- Loads entire event dataset into memory
- Multiple iterations over large datasets
- Unnecessary data transfer

**Recommendation:**
```python
# Use SQL aggregation
from sqlalchemy import func

query = select(Event.state, func.count(Event.id)).group_by(Event.state)
result = await db.execute(query)
state_counts = dict(result.all())
```

**Priority:** 🔴 **HIGH**

---

#### 3. **No Database Connection Pooling Configuration** 🟡
**Location:** `app/database.py:27-32`

**Issue:** No explicit connection pool settings.

**Impact:**
- Default pool may be insufficient under load
- No control over connection limits
- Potential connection exhaustion

**Recommendation:**
```python
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=3600,   # Recycle connections after 1 hour
)
```

**Priority:** 🟡 **MEDIUM**

---

#### 4. **No Caching** 🟡
**Location:** Throughout application

**Issue:** No caching layer for frequently accessed data.

**Impact:**
- Repeated database queries for same data
- Unnecessary load on database
- Slower response times

**Recommendation:**
- Implement Redis or in-memory caching for:
  - Community lists
  - Event counts
  - State filters
- Cache TTL: 5-15 minutes for dynamic data

**Priority:** 🟡 **MEDIUM**

---

#### 5. **No Pagination** 🟡
**Location:** `app/controllers/event_controller.py:101-134`

**Issue:** All events loaded at once without pagination.

**Impact:**
- Memory usage grows with dataset size
- Slow response times for large datasets
- Poor user experience

**Recommendation:**
```python
async def get_upcoming_events(
    self,
    state: Optional[str] = None,
    community_id: Optional[int] = None,
    limit: int = 50,
    offset: int = 0
) -> List[EventResponse]:
    query = select(Event).where(...).limit(limit).offset(offset)
```

**Priority:** 🟡 **MEDIUM**

---

#### 6. **Synchronous Email Sending** 🟡
**Location:** `app/controllers/ticket_controller.py:14`

**Issue:** Email service called synchronously, blocking request.

**Impact:**
- Slow response times
- Request timeout risk
- Poor user experience

**Recommendation:**
- Use background task queue (Celery, RQ, or FastAPI BackgroundTasks)
- Return response immediately
- Send email asynchronously

**Priority:** 🟡 **MEDIUM**

---

#### 7. **Database Query Logging Overhead** 🟢
**Location:** `app/database.py:27`

**Issue:** `echo=True` logs all queries, adding I/O overhead.

**Impact:**
- Performance degradation
- Log file bloat

**Recommendation:** Disable in production (see Security Issue #7)

**Priority:** 🟢 **LOW**

---

### Performance Strengths ✅

1. **Async/Await:** ✅ Properly used throughout
2. **SQLAlchemy ORM:** ✅ Efficient query building
3. **Static File Serving:** ✅ Properly configured
4. **Template Caching:** ✅ Jinja2 handles this

---

## 📊 Load & Stress Testing Readiness

### Critical Scalability Issues

#### 1. **SQLite Limitations** 🔴
**Location:** `app/database.py:24`

**Issue:** SQLite is not designed for high-concurrency production workloads.

**Limitations:**
- Single writer at a time (write lock)
- Poor concurrent write performance
- No built-in replication
- Limited scalability

**Impact:**
- Database locks under concurrent load
- Request queuing and timeouts
- Poor performance with multiple users

**Recommendation:**
- Migrate to PostgreSQL for production
- Use asyncpg for async PostgreSQL driver
- Implement connection pooling
- Consider read replicas for scaling

**Priority:** 🔴 **HIGH** - Critical for scale

---

#### 2. **No Request Timeout Configuration** 🟡
**Location:** `main.py`, `fly.toml`

**Issue:** No explicit request timeout settings.

**Impact:**
- Long-running requests can tie up resources
- No protection against slow queries
- Resource exhaustion risk

**Recommendation:**
```python
# In uvicorn config
uvicorn.run(
    app,
    host="0.0.0.0",
    port=port,
    timeout_keep_alive=5,
    timeout_graceful_shutdown=10
)
```

**Priority:** 🟡 **MEDIUM**

---

#### 3. **No Resource Limits** 🟡
**Location:** `fly.toml`

**Issue:** No memory or CPU limits configured.

**Impact:**
- Unbounded resource usage
- Potential OOM (Out of Memory) crashes
- Cost overruns

**Recommendation:**
```toml
[[vm]]
  memory_mb = 512
  cpu_kind = "shared"
```

**Priority:** 🟡 **MEDIUM**

---

#### 4. **No Database Indexing Strategy** 🟡
**Location:** Models

**Issue:** Limited explicit indexing on frequently queried fields.

**Impact:**
- Slow queries on large datasets
- Full table scans

**Recommendation:**
```python
class Event(SQLModel, table=True):
    state: str = Field(index=True)  # For filtering
    start_date: date = Field(index=True)  # For date queries
    community_id: Optional[int] = Field(default=None, foreign_key="community.id", index=True)
```

**Priority:** 🟡 **MEDIUM**

---

#### 5. **Single Instance Deployment** 🟡
**Location:** `fly.toml:15`

**Issue:** `min_machines_running = 1` - no redundancy.

**Impact:**
- Single point of failure
- No load distribution
- Downtime during deployments

**Recommendation:**
- Set `min_machines_running = 2` for redundancy
- Implement health checks
- Use load balancer

**Priority:** 🟡 **MEDIUM**

---

#### 6. **No Monitoring/Alerting** 🟢
**Location:** Application-wide

**Issue:** No application performance monitoring (APM) or alerting.

**Impact:**
- No visibility into performance issues
- No proactive problem detection
- Difficult troubleshooting

**Recommendation:**
- Implement Sentry for error tracking
- Add Prometheus metrics
- Set up Grafana dashboards
- Configure alerts for:
  - High error rates
  - Slow response times
  - Database connection issues

**Priority:** 🟢 **LOW** (but recommended)

---

## 📋 Recommendations Summary

### Immediate Actions (Critical - Fix Before Production Scale)

1. ✅ **Fix CORS configuration** - Restrict to specific origins
2. ✅ **Implement CSRF protection** - Add tokens to all forms
3. ✅ **Add rate limiting** - Protect all endpoints
4. ✅ **Fix N+1 query problem** - Optimize event loading
5. ✅ **Optimize state counting** - Use SQL aggregation
6. ✅ **Migrate from SQLite to PostgreSQL** - For production scale

### Short-term Improvements (High Priority)

1. ✅ **Add security headers middleware**
2. ✅ **Strengthen password policy** - 12+ chars, complexity
3. ✅ **Implement pagination** - For all list endpoints
4. ✅ **Add connection pooling configuration**
5. ✅ **Implement caching layer** - Redis or in-memory
6. ✅ **Add request timeouts**
7. ✅ **Validate URL inputs** - Prevent XSS/redirect attacks

### Medium-term Enhancements

1. ✅ **Add database indexes** - On frequently queried fields
2. ✅ **Implement background tasks** - For email sending
3. ✅ **Add monitoring/alerting** - APM and error tracking
4. ✅ **Configure resource limits** - Memory and CPU
5. ✅ **Add redundancy** - Multiple instances
6. ✅ **Implement database backups** - Automated backups

### Long-term Considerations

1. ✅ **Consider microservices** - If scale requires
2. ✅ **Implement CDN** - For static assets
3. ✅ **Add search functionality** - Full-text search (Elasticsearch)
4. ✅ **Implement API versioning** - For future changes
5. ✅ **Add comprehensive logging** - Structured logging

---

## 🧪 Load Testing Recommendations

### Test Scenarios

1. **Baseline Load Test**
   - 10 concurrent users
   - 5-minute duration
   - Measure response times, error rates

2. **Stress Test**
   - Gradually increase to 100 concurrent users
   - Identify breaking points
   - Monitor database locks

3. **Spike Test**
   - Sudden increase to 200 users
   - Test recovery time
   - Check for crashes

4. **Endurance Test**
   - 50 concurrent users for 1 hour
   - Check for memory leaks
   - Monitor database growth

### Tools Recommended

- **Locust** - Python-based load testing
- **k6** - Modern load testing tool
- **Apache Bench (ab)** - Simple HTTP benchmarking
- **Artillery** - Node.js load testing

### Key Metrics to Monitor

- Response time (p50, p95, p99)
- Error rate
- Throughput (requests/second)
- Database connection pool usage
- Memory usage
- CPU usage
- Database lock wait times

---

## 📊 Risk Assessment Matrix

| Issue | Severity | Likelihood | Impact | Priority |
|-------|----------|------------|--------|----------|
| CORS Configuration | High | High | High | 🔴 Critical |
| Missing CSRF Protection | High | Medium | High | 🔴 Critical |
| N+1 Query Problem | High | High | Medium | 🔴 Critical |
| No Rate Limiting | High | High | High | 🔴 Critical |
| SQLite Limitations | High | High | High | 🔴 Critical |
| Weak Password Policy | Medium | Medium | Medium | 🟡 High |
| Inefficient State Counting | Medium | High | Medium | 🟡 High |
| No Caching | Medium | High | Medium | 🟡 High |
| Missing Security Headers | Medium | Low | Medium | 🟡 Medium |
| URL Validation | Medium | Low | Low | 🟡 Medium |
| No Pagination | Low | High | Low | 🟢 Low |
| Database Logging | Low | High | Low | 🟢 Low |

---

## ✅ Conclusion

The Bayan Events Platform demonstrates solid foundational security practices (password hashing, secure sessions, SQL injection prevention) but has several critical gaps that must be addressed before handling production-scale traffic:

1. **Security:** CORS, CSRF, and rate limiting are critical missing pieces
2. **Performance:** N+1 queries and inefficient counting will cause issues at scale
3. **Scalability:** SQLite is not suitable for production workloads with concurrent users

**Estimated Effort to Address Critical Issues:** 2-3 weeks

**Recommended Timeline:**
- Week 1: Fix critical security issues (CORS, CSRF, rate limiting)
- Week 2: Optimize performance (N+1 queries, state counting, pagination)
- Week 3: Database migration planning and execution (SQLite → PostgreSQL)

---

**Report Generated:** January 16, 2026  
**Next Review:** After implementing critical fixes

