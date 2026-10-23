import os,tempfile,unittest
import app as portal

class PortalSecurityTests(unittest.TestCase):
 def setUp(self):
  self.f=tempfile.NamedTemporaryFile(delete=False); self.f.close()
  portal.DB=self.f.name; portal.init_db()
  portal.app.config.update(TESTING=True,SECRET_KEY="test-secret")
  self.c=portal.app.test_client()
 def tearDown(self): os.unlink(self.f.name)
 def token(self):
  with self.c.session_transaction() as s: return s["_csrf"]
 def login(self,email="alice@example.com",pw="AliceDemo!23"):
  self.c.get("/"); return self.c.post("/",data={"csrf_token":self.token(),"email":email,"password":pw},follow_redirects=True)
 def test_password_is_verified(self):
  self.c.get("/"); r=self.login(pw="wrong")
  self.assertIn(b"Invalid email or password",r.data)
 def test_login_and_security_headers(self):
  r=self.login(); self.assertIn(b"Account overview",r.data)
  self.assertEqual(r.headers["X-Frame-Options"],"DENY")
 def test_csrf_required(self):
  self.login(); r=self.c.post("/add",data={"amount":"10","kind":"expense","description":"test"})
  self.assertEqual(r.status_code,400)
 def test_negative_amount_rejected(self):
  self.login(); r=self.c.post("/add",data={"csrf_token":self.token(),"amount":"-10","kind":"expense","description":"bad"})
  self.assertEqual(r.status_code,400)
 def test_user_isolation(self):
  self.login(); self.c.post("/add",data={"csrf_token":self.token(),"amount":"20","kind":"expense","description":"Alice secret"})
  self.c.post("/logout",data={"csrf_token":self.token()}); self.login("bob@example.com","BobDemoPass!23")
  self.assertNotIn(b"Alice secret",self.c.get("/").data)
 def test_logout_get_not_allowed(self):
  self.login(); self.assertEqual(self.c.get("/logout").status_code,405)

if __name__=="__main__": unittest.main()
