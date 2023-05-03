import jwt # PyJWT version 1.5.3 as of the time of authoring.
import uuid
import requests # requests version 2.18.4 as of the time of authoring.
import json
from datetime import datetime, timedelta
# 30 minutes from now
timeout = 1800
now = datetime.utcnow()
timeout_datetime = now + timedelta(seconds=timeout)
epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
jti_val = str(uuid.uuid4())
tid_val = "f4401cd1-6d3a-4557-9283-f7a077db42e4" # The tenant's unique identifier.
app_id = "29b7dea9-6a46-4817-92c0-e799721561dd" # The application's unique identifier.
app_secret = "f800b298-8620-40cc-98a8-a2e5fcb1c46c" # The application's secret to sign the auth token with.
AUTH_URL = "https://protectapi.cylance.com/auth/v2/token"
claims = {
"exp": epoch_timeout,
"iat": epoch_time,
"iss": "http://cylance.com",
"sub": app_id,
"tid": tid_val,
"jti": jti_val
# The following is optional and is being noted here as an example on how one can restrict
# the list of scopes being requested
# "scp": "policy:create, policy:list, policy:read, policy:update"
}
encoded = jwt.encode(claims, app_secret, algorithm='HS256')
print "auth_token:\n" + encoded + "\n"
payload = {"auth_token": encoded}
headers = {"Content-Type": "application/json; charset=utf-8"}
resp = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
print "http_status_code: " + str(resp.status_code)
print "access_token:\n" + json.loads(resp.text)['access_token'] + "\n"