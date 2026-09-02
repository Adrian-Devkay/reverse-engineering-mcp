# Authorized web reconnaissance and evidence collection

Use this mode only for a web origin, application, or API that the user owns or
has explicitly authorized. Create a web case first. Its safe defaults deny
lab-only exceptions; enable those exceptions in the manifest before use:

```text
python scripts/init_web_case.py CASE_DIR \
  --authorization "written authorization for the named test environment" \
  --scope example.test
```

Then run the bounded collector with one or more in-scope seeds:

```text
python scripts/web_recon.py CASE_DIR https://example.test/
```

The collector is intentionally conservative:

- exact scope plus subdomain matching from `web-case.json`;
- HTTP and HTTPS only, with credentials in URLs rejected;
- GET-only requests, no cookies, no authorization headers, no form submission,
  no JavaScript execution, and no arbitrary command execution;
- robots.txt respected by default and failed-closed when policy cannot be read;
- redirects revalidated against scope and network destination before following;
- public destinations only by default, with loopback/private addresses requiring
  an explicit isolated-lab flag;
- bounded pages, depth, response bytes, total bytes, timeout, and delay;
- query values and page bodies are not written to the report;
- private-network access, non-standard ports, and ignoring robots.txt are
  rejected unless the corresponding manifest policy flag is explicitly true;
- only selected response headers, redacted URLs, response hashes, link metadata,
  status, and errors are retained.

The report is evidence, not proof of a vulnerability. Use it to inventory
authorized attack surface, then validate individual hypotheses with the smallest
safe request set. Do not turn this collector into endpoint brute forcing,
credential testing, exploit delivery, denial-of-service testing, or broad
third-party crawling. For authenticated or active testing, stop and obtain a
narrowly defined authorization and use a separately isolated runner.
