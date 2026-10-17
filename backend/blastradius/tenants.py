"""Curated tenants: two real public projects treated as two 'companies'.

Dependencies come from their real lockfiles; the service call graph and internet exposure are DISCOVERED from
their deployment files (see discover.py). `reference_calls` is the hand-written list from the projects' docs and
is used only by the evals to cross-check discovery. `supplement_*` covers the few facts no deployment file holds.
"""

TENANTS = {
    "otel": {
        "title": "OpenTelemetry Demo",
        "repo": "open-telemetry/opentelemetry-demo",
        "branch": "main",
        "codeowners": ".github/CODEOWNERS",
        "services": [
            {"name": "frontend-proxy", "path": "src/frontend-proxy", "kind": "none"},
            {"name": "frontend", "path": "src/frontend", "kind": "npm", "file": "package-lock.json"},
            {"name": "payment", "path": "src/payment", "kind": "npm", "file": "package-lock.json"},
            {"name": "react-native-app", "path": "src/react-native-app", "kind": "npm", "file": "package-lock.json"},
            {"name": "checkout", "path": "src/checkout", "kind": "gomod", "file": "go.mod"},
            {"name": "product-catalog", "path": "src/product-catalog", "kind": "gomod", "file": "go.mod"},
            {"name": "recommendation", "path": "src/recommendation", "kind": "none"},
            {"name": "cart", "path": "src/cart", "kind": "none"},
            {"name": "ad", "path": "src/ad", "kind": "none"},
            {"name": "currency", "path": "src/currency", "kind": "none"},
            {"name": "shipping", "path": "src/shipping", "kind": "none"},
            {"name": "email", "path": "src/email", "kind": "none"},
            {"name": "accounting", "path": "src/accounting", "kind": "none"},
            {"name": "fraud-detection", "path": "src/fraud-detection", "kind": "none"},
            {"name": "agent", "path": "src/agent", "kind": "requirements", "file": "requirements.txt"},
            {"name": "mcp", "path": "src/mcp", "kind": "requirements", "file": "requirements.txt"},
            {"name": "chatbot", "path": "src/chatbot", "kind": "requirements", "file": "requirements.txt"},
            {"name": "load-generator", "path": "src/load-generator", "kind": "requirements", "file": "requirements.txt"},
        ],
        "discover": {"kind": "compose", "files": ["compose.yaml", "compose.agent.yaml"]},
        "supplement_calls": [("react-native-app", "frontend-proxy")],
        "supplement_exposed": ["react-native-app"],  # a mobile client on users' devices: no deployment file says so
        "reference_calls": [
            ("frontend", "checkout"), ("frontend", "cart"), ("frontend", "product-catalog"),
            ("frontend", "currency"), ("frontend", "ad"), ("frontend", "recommendation"),
            ("frontend", "shipping"), ("checkout", "cart"), ("checkout", "currency"), ("checkout", "email"),
            ("checkout", "payment"), ("checkout", "product-catalog"), ("checkout", "shipping"),
            ("recommendation", "product-catalog"),
        ],
    },
    "boutique": {
        "title": "Online Boutique",
        "repo": "GoogleCloudPlatform/microservices-demo",
        "branch": "main",
        "codeowners": ".github/CODEOWNERS",
        "services": [
            {"name": "frontend", "path": "src/frontend", "kind": "gomod", "file": "go.mod"},
            {"name": "checkoutservice", "path": "src/checkoutservice", "kind": "gomod", "file": "go.mod"},
            {"name": "productcatalogservice", "path": "src/productcatalogservice", "kind": "gomod", "file": "go.mod"},
            {"name": "shippingservice", "path": "src/shippingservice", "kind": "gomod", "file": "go.mod"},
            {"name": "currencyservice", "path": "src/currencyservice", "kind": "npm", "file": "package-lock.json"},
            {"name": "paymentservice", "path": "src/paymentservice", "kind": "npm", "file": "package-lock.json"},
            {"name": "emailservice", "path": "src/emailservice", "kind": "requirements", "file": "requirements.txt"},
            {"name": "recommendationservice", "path": "src/recommendationservice", "kind": "requirements", "file": "requirements.txt"},
            {"name": "shoppingassistantservice", "path": "src/shoppingassistantservice", "kind": "requirements", "file": "requirements.txt"},
            {"name": "loadgenerator", "path": "src/loadgenerator", "kind": "requirements", "file": "requirements.txt"},
            {"name": "cartservice", "path": "src/cartservice", "kind": "none"},
            {"name": "adservice", "path": "src/adservice", "kind": "none"},
        ],
        "discover": {
            "kind": "kubernetes",
            "files": [f"kubernetes-manifests/{n}.yaml" for n in (
                "frontend", "checkoutservice", "productcatalogservice", "shippingservice", "currencyservice",
                "paymentservice", "emailservice", "recommendationservice", "loadgenerator", "cartservice", "adservice")],
        },
        "supplement_calls": [],
        "supplement_exposed": [],
        "reference_calls": [
            ("frontend", "checkoutservice"), ("frontend", "cartservice"), ("frontend", "productcatalogservice"),
            ("frontend", "currencyservice"), ("frontend", "adservice"), ("frontend", "recommendationservice"),
            ("frontend", "shippingservice"), ("frontend", "shoppingassistantservice"),
            ("checkoutservice", "cartservice"), ("checkoutservice", "currencyservice"),
            ("checkoutservice", "emailservice"), ("checkoutservice", "paymentservice"),
            ("checkoutservice", "productcatalogservice"), ("checkoutservice", "shippingservice"),
            ("recommendationservice", "productcatalogservice"), ("loadgenerator", "frontend"),
            ("shoppingassistantservice", "productcatalogservice"),
        ],
    },
    "anthos": {
        "title": "Bank of Anthos",
        "repo": "GoogleCloudPlatform/bank-of-anthos",
        "branch": "main",
        "codeowners": ".github/CODEOWNERS",
        "expand": True,  # Java poms list direct dependencies only; resolve the transitive graph through deps.dev
        "services": [
            {"name": "frontend", "path": "src/frontend", "kind": "uv", "file": "uv.lock"},
            {"name": "userservice", "path": "src/accounts/userservice", "kind": "uv", "file": "uv.lock"},
            {"name": "contacts", "path": "src/accounts/contacts", "kind": "uv", "file": "uv.lock"},
            {"name": "loadgenerator", "path": "src/loadgenerator", "kind": "uv", "file": "uv.lock"},
            {"name": "balancereader", "path": "src/ledger/balancereader", "kind": "maven", "file": "pom.xml"},
            {"name": "ledgerwriter", "path": "src/ledger/ledgerwriter", "kind": "maven", "file": "pom.xml"},
            {"name": "transactionhistory", "path": "src/ledger/transactionhistory", "kind": "maven", "file": "pom.xml"},
            {"name": "accounts-db", "path": "src/accounts/accounts-db", "kind": "none"},
            {"name": "ledger-db", "path": "src/ledger/ledger-db", "kind": "none"},
        ],
        "discover": {
            "kind": "kubernetes",
            "files": [f"kubernetes-manifests/{n}.yaml" for n in (
                "config", "frontend", "userservice", "contacts", "ledger-writer", "balance-reader", "transaction-history",
                "loadgenerator", "accounts-db", "ledger-db")],
        },
        "supplement_calls": [],
        "supplement_exposed": [],
        # from the project's architecture diagram (README), used only to cross-check discovery in the evals
        "reference_calls": [
            ("frontend", "userservice"), ("frontend", "contacts"), ("frontend", "ledgerwriter"),
            ("frontend", "balancereader"), ("frontend", "transactionhistory"), ("ledgerwriter", "balancereader"),
            ("userservice", "accounts-db"), ("contacts", "accounts-db"), ("ledgerwriter", "ledger-db"),
            ("balancereader", "ledger-db"), ("transactionhistory", "ledger-db"), ("loadgenerator", "frontend"),
        ],
    },
}
