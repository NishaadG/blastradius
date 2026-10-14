"""Tenant definitions. Each tenant is a real public project, treated as a 'company'.

Service-to-service CALLS edges are curated from each project's public architecture docs
(README / docs). Dependency data comes from the real lockfiles in the repos.
"""

TENANTS = {
    "otel": {
        "title": "OpenTelemetry Demo",
        "repo": "open-telemetry/opentelemetry-demo",
        "branch": "main",
        "codeowners": ".github/CODEOWNERS",
        "services": [
            {"name": "frontend", "path": "src/frontend", "kind": "npm", "file": "package-lock.json", "exposed": True},
            {"name": "payment", "path": "src/payment", "kind": "npm", "file": "package-lock.json"},
            {"name": "react-native-app", "path": "src/react-native-app", "kind": "npm", "file": "package-lock.json", "exposed": True},
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
        "calls": [
            ("frontend", "checkout"), ("frontend", "cart"), ("frontend", "product-catalog"),
            ("frontend", "currency"), ("frontend", "ad"), ("frontend", "recommendation"),
            ("frontend", "shipping"), ("react-native-app", "frontend"),
            ("checkout", "cart"), ("checkout", "currency"), ("checkout", "email"),
            ("checkout", "payment"), ("checkout", "product-catalog"), ("checkout", "shipping"),
            ("checkout", "accounting"), ("checkout", "fraud-detection"),
            ("recommendation", "product-catalog"), ("load-generator", "frontend"),
            ("chatbot", "mcp"), ("mcp", "product-catalog"), ("agent", "mcp"),
        ],
    },
    "boutique": {
        "title": "Online Boutique",
        "repo": "GoogleCloudPlatform/microservices-demo",
        "branch": "main",
        "codeowners": ".github/CODEOWNERS",
        "services": [
            {"name": "frontend", "path": "src/frontend", "kind": "gomod", "file": "go.mod", "exposed": True},
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
        "calls": [
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
}
