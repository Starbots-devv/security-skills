# Deterministic boundary cases

The harness sends requests attributed to untrusted documents, tool responses, metadata, repository instructions, memory, tool schemas and replayed approval text. It also tests wrong-client identity, path traversal, absolute paths, extra approval flags and extra tool arguments. The authorized read is a positive control; blanket denial cannot pass the experiment.

Only `read_artifact` inside the independently selected artifact root is implemented, with a 1 MiB bound. Shell, network, approval signing, deployment, tool installation, deletion and AWS application have no dispatcher capability. Requests are closed-schema data. This test does not run an MCP transport or sample a language model. It demonstrates software authorization decisions for this finite corpus; host permissions and model behavior remain separate evaluations.
