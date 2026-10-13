"""Direct positive and negative tests for rules that were previously only exercised through the demo project."""
import unittest

from tests.helpers import ids

PY = {"app", "lang:python"}
JS = {"app", "lang:javascript"}
K8S = {"kubernetes"}
DF = {"dockerfile"}
GHA = {"github-actions"}
TF = {"terraform"}


class AppCoreRules(unittest.TestCase):
    def test_tls_verification_off(self):
        self.assertIn("ACR-APP-005", ids("a.py", "requests.get(url, verify=False)\n", PY))
        self.assertIn("ACR-APP-005", ids("a.js", "new https.Agent({ rejectUnauthorized: false });\n", JS))
        self.assertNotIn("ACR-APP-005", ids("a.py", "requests.get(url, verify='/etc/ssl/ca.pem')\n", PY))

    def test_debug_mode(self):
        self.assertIn("ACR-APP-006", ids("app.py", "app.run(host='0.0.0.0', debug=True)\n", PY))
        self.assertIn("ACR-APP-006", ids("settings.py", "DEBUG = True\n", PY))
        self.assertNotIn("ACR-APP-006", ids("settings.py", "DEBUG = env.bool('DEBUG', default=False)\n", PY))


class AiCoreRules(unittest.TestCase):
    def test_provider_key_in_browser(self):
        js_ai = JS | {"ai-code"}
        self.assertIn("ACR-AI-006", ids("c.js", "const client = new OpenAI({ dangerouslyAllowBrowser: true });\n", js_ai))
        self.assertIn("ACR-AI-006", ids("c.ts", "const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n",
                                        {"app", "lang:typescript"}))
        self.assertNotIn("ACR-AI-006", ids("c.js", "const key = process.env.OPENAI_API_KEY;\n", JS))


class McpCoreRules(unittest.TestCase):
    def test_plain_http_and_broad_access(self):
        mcp = {"mcp-config"}
        self.assertIn("ACR-MCP-003", ids(".mcp.json", '{"mcpServers": {"r": {"url": "http://mcp.example.com/sse"}}}', mcp))
        self.assertIn("ACR-MCP-003", ids(".mcp.json", '{"mcpServers": {"fs": {"command": "mcp-fs", "args": ["/"]}}}', mcp))
        local = '{"mcpServers": {"r": {"url": "http://localhost:8080/sse"}, "fs": {"command": "mcp-fs", "args": ["./docs"]}}}'
        self.assertNotIn("ACR-MCP-003", ids(".mcp.json", local, mcp))


class KubernetesCoreRules(unittest.TestCase):
    def test_dangerous_capabilities(self):
        self.assertIn("ACR-K8S-004", ids("p.yaml", "capabilities:\n  add: [\"SYS_ADMIN\"]\n", K8S))
        self.assertIn("ACR-K8S-004", ids("p.yaml", "capabilities:\n  add:\n    - NET_ADMIN\n", K8S))
        self.assertNotIn("ACR-K8S-004", ids("p.yaml", "capabilities:\n  drop: [\"ALL\"]\n  add: [\"NET_BIND_SERVICE\"]\n", K8S))

    def test_runs_as_root(self):
        self.assertIn("ACR-K8S-006", ids("p.yaml", "securityContext:\n  runAsUser: 0\n", K8S))
        self.assertIn("ACR-K8S-006", ids("p.yaml", "securityContext:\n  runAsNonRoot: false\n", K8S))
        self.assertNotIn("ACR-K8S-006", ids("p.yaml", "securityContext:\n  runAsUser: 10001\n", K8S))


class DockerfileCoreRules(unittest.TestCase):
    def _df(self, line):
        return ids("Dockerfile", f"FROM python:3.12-slim\n{line}\nUSER 10001\n", DF)

    def test_add_remote_url(self):
        self.assertIn("ACR-DOCKER-004", self._df("ADD https://example.com/tool.tgz /opt/"))
        self.assertNotIn("ACR-DOCKER-004", self._df("ADD vendor.tgz /opt/"))

    def test_secret_in_env_or_arg(self):
        self.assertIn("ACR-DOCKER-005", self._df("ENV API_TOKEN=abc123"))
        self.assertIn("ACR-DOCKER-005", self._df("ARG NPM_TOKEN=xyz"))
        self.assertNotIn("ACR-DOCKER-005", self._df("ENV PORT=8080"))

    def test_package_cache_and_sudo(self):
        self.assertIn("ACR-DOCKER-006", self._df("RUN apt-get update && apt-get install -y curl"))
        self.assertIn("ACR-DOCKER-006", self._df("RUN apk add sudo && rm -rf /var/lib/apt/lists/*"))
        self.assertNotIn("ACR-DOCKER-006", self._df("RUN apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*"))


class WorkflowCoreRules(unittest.TestCase):
    def _wf(self, run):
        return ids(".github/workflows/x.yml", f"permissions: {{}}\njobs:\n  a:\n    steps:\n      - run: {run}\n", GHA)

    def test_secret_printed(self):
        self.assertIn("ACR-GHA-005", self._wf("echo ${{ secrets.DEPLOY_KEY }}"))
        self.assertNotIn("ACR-GHA-005", self._wf("echo deploying"))

    def test_deprecated_commands(self):
        self.assertIn("ACR-GHA-006", self._wf('echo "::set-output name=v::1"'))
        self.assertNotIn("ACR-GHA-006", self._wf('echo "v=1" >> "$GITHUB_OUTPUT"'))


class TerraformCoreRules(unittest.TestCase):
    def test_public_data(self):
        self.assertIn("ACR-TF-002", ids("s.tf", 'resource "aws_s3_bucket_acl" "a" {\n  acl = "public-read"\n}\n', TF))
        self.assertIn("ACR-TF-002", ids("d.tf", 'resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}\n', TF))
        self.assertNotIn("ACR-TF-002", ids("s.tf", 'resource "aws_s3_bucket_acl" "a" {\n  acl = "private"\n}\n', TF))

    def test_weak_encryption(self):
        self.assertIn("ACR-TF-003", ids("d.tf", 'resource "aws_db_instance" "d" {\n  storage_encrypted = false\n}\n', TF))
        self.assertIn("ACR-TF-003", ids("s.tf", 'resource "azurerm_storage_account" "s" {\n  min_tls_version = "TLS1_0"\n}\n', TF))
        self.assertNotIn("ACR-TF-003", ids("s.tf", 'resource "azurerm_storage_account" "s" {\n  min_tls_version = "TLS1_2"\n}\n', TF))

    def test_wildcard_iam(self):
        self.assertIn("ACR-TF-004", ids("i.tf", 'resource "google_project_iam_member" "m" {\n  role = "roles/owner"\n}\n', TF))
        self.assertIn("ACR-TF-004", ids("i.tf", 'data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["*"]\n  }\n}\n', TF))
        self.assertNotIn("ACR-TF-004", ids("i.tf", 'resource "google_project_iam_member" "m" {\n  role = "roles/viewer"\n}\n', TF))

    def test_public_control_plane(self):
        self.assertIn("ACR-TF-005", ids("e.tf", 'resource "aws_eks_cluster" "c" {\n  vpc_config {\n    endpoint_public_access = true\n  }\n}\n', TF))
        self.assertNotIn("ACR-TF-005", ids("e.tf", 'resource "aws_eks_cluster" "c" {\n  vpc_config {\n    endpoint_public_access = false\n  }\n}\n', TF))

    def test_unpinned_modules(self):
        self.assertIn("ACR-TF-006", ids("m.tf", 'module "vpc" {\n  source = "git::https://github.com/org/vpc.git"\n}\n', TF))
        self.assertIn("ACR-TF-006", ids("m.tf", 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n', TF))
        pinned = ('module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n  version = "5.8.1"\n}\n'
                  'module "net" {\n  source = "git::https://github.com/org/net.git?ref=v1.2.0"\n}\n'
                  'module "local" {\n  source = "./modules/x"\n}\n')
        self.assertNotIn("ACR-TF-006", ids("m.tf", pinned, TF))
