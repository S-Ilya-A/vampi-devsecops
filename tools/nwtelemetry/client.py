"""A minimal OpenSearch REST client (urllib, TLS verified against a CA file)."""
import base64
import json
import ssl
import urllib.error
import urllib.request


class OpenSearchError(RuntimeError):
    pass


class OpenSearch:
    def __init__(self, url, user=None, password=None, ca_file=None, timeout=30):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json"}
        if user:
            cred = base64.b64encode(("%s:%s" % (user, password or "")).encode()).decode()
            self.headers["Authorization"] = "Basic " + cred
        self.ctx = ssl.create_default_context(cafile=ca_file) if self.url.startswith("https") else None

    def request(self, method, path, body=None, ndjson=False):
        if body is None:
            data = None
        elif ndjson:
            data = body.encode()
        else:
            data = json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=dict(self.headers))
        if ndjson:
            req.add_header("Content-Type", "application/x-ndjson")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            if e.code == 404 and method == "POST" and path.endswith("/_search"):
                # No index matches the pattern yet: an empty result, not an error.
                return {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}
            raise OpenSearchError("%s %s: HTTP %s %s" % (method, path, e.code, detail)) from None
        except urllib.error.URLError as e:
            raise OpenSearchError("%s %s: %s" % (method, path, e.reason)) from None
        return json.loads(raw) if raw else {}

    def bulk(self, actions):
        """actions: iterable of (index, doc_id, document). Indexes (upserts) them;
        a fixed id makes a re-run overwrite instead of duplicating."""
        lines, n = [], 0
        for index, doc_id, doc in actions:
            lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
            lines.append(json.dumps(doc, default=str))
            n += 1
        if not n:
            return 0
        res = self.request("POST", "/_bulk?refresh=wait_for", "\n".join(lines) + "\n", ndjson=True)
        if res.get("errors"):
            errs = [i["index"]["error"] for i in res["items"] if "error" in i.get("index", {})]
            raise OpenSearchError("bulk: %d of %d failed, first: %s" % (len(errs), n, errs[0]))
        return n

    def search(self, index, body):
        return self.request("POST", "/%s/_search?ignore_unavailable=true&allow_no_indices=true" % index, body)
