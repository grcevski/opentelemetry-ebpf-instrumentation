# Rust context propagation fixture

The Tokio server spawns nested tasks and reuses a reqwest client for downstream
requests. The integration matrix exercises both Tokio schedulers and checks the
parent and wire header on each request.
