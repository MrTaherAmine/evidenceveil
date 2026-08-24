# Plugin Development

Plugins are trusted Python code and execute with the user's privileges. Do not install plugins from untrusted sources. The example `ExampleTicketDetector` demonstrates the semantic detector interface. Future plugin types should expose explicit, typed entry points rather than arbitrary import-time discovery.
