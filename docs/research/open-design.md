# OpenDesign integration research

Reviewed upstream revision [`12d970eacc8971150e3c76470d2a9afe16dc2ed1`](https://github.com/nexu-io/open-design/tree/12d970eacc8971150e3c76470d2a9afe16dc2ed1). This is a source review, not a working integration or legal opinion.

## Conclusion

OpenDesign can potentially supply HTML to artifact-host without a required OpenDesign software-license fee. Start with an export-and-publish workflow, not embedding its daemon or handing it artifact-host's admin credential. This path has not been tested end to end.

## License and cost

- The [upstream LICENSE](https://github.com/nexu-io/open-design/blob/12d970eacc8971150e3c76470d2a9afe16dc2ed1/LICENSE) is Apache 2.0. It permits use, modification, and distribution subject to its conditions, including preservation of applicable notices. The [README](https://github.com/nexu-io/open-design/blob/12d970eacc8971150e3c76470d2a9afe16dc2ed1/README.md#license) notes that some bundled skills and templates retain separate licenses. Check the specific components and assets before copying or redistributing them.
- [Upstream documents](https://github.com/nexu-io/open-design/blob/12d970eacc8971150e3c76470d2a9afe16dc2ed1/README.md#why-opendesign) local or self-hosted operation and bring-your-own-key providers, including Ollama. Software license does not cover compute, storage, cloud service, or model-provider charges. A local-model setup could avoid a model API fee, but hardware and electricity still cost money. No specific model's suitability or price was tested.
- The same README says product analytics and session replay are consent-gated, while scrubbed safety and reliability telemetry is always on. Verify current upstream behavior and privacy requirements before deployment.

## Integration options

1. **Export and publish, recommended first.** The [README](https://github.com/nexu-io/open-design/blob/12d970eacc8971150e3c76470d2a9afe16dc2ed1/README.md#demo) describes single-page HTML prototypes and single-file HTML deck exports. Put a suitable export at `index.html` in a directory, then use existing `ah publish`. Artifact-host requires a root `index.html` and accepts static files; it cannot host OpenDesign's server-side application. Verify asset paths, export format, CSP behavior, and private-site access with representative exports. Not all OpenDesign outputs are necessarily suitable as standalone static sites.
2. **Agent-assisted handoff.** Upstream describes [MCP and CLI project-file access](https://github.com/nexu-io/open-design/blob/12d970eacc8971150e3c76470d2a9afe16dc2ed1/README.md#use-opendesign-from-your-coding-agent), including Pi support. An agent could retrieve or export suitable files and invoke `ah publish`. This is a proposed workflow, not a verified automatic export API. Avoid publishing source trees, secrets, or credentials.
3. **Deeper application integration.** A separate OpenDesign service could add an integrated design experience, but introduces process execution, network, authentication, and operational boundaries. Upstream [deployment guidance](https://github.com/nexu-io/open-design/blob/12d970eacc8971150e3c76470d2a9afe16dc2ed1/deploy/README.md) states its API token is single-tenant authentication, not per-user access control. Do not equate that token with artifact-host user/team ACLs. Multi-user isolation requires separate design and review.

## Compatibility and security checks before implementation

- Artifact-host requires root `index.html`, limits the upload body to 32 MiB, and serves published files under a CSP sandbox. Dynamic requests, embedded assets, or preview messaging may behave differently from OpenDesign's own preview. Test actual exported artifacts rather than assuming equivalence.
- Owner/team artifacts require bearer authorization on reads. Browser links alone do not provide that token; a handoff must not claim otherwise or put tokens in URLs.
- Keep OpenDesign and its credentials separate from artifact-host's admin origin and token. Current artifact-host serves user content and admin on the same origin; its sandbox is a mitigation, not a separate-origin boundary.
- Upstream's [deployment guide](https://github.com/nexu-io/open-design/blob/12d970eacc8971150e3c76470d2a9afe16dc2ed1/deploy/README.md) calls for authenticated TLS and exact allowed origins for remote deployments. Review those requirements and upstream security documentation before exposing any service.

## Next decision

Choose whether the spec should cover only a documented manual export-and-publish handoff, an agent-assisted handoff, or a separate deeper integration effort. No integration was implemented or tested in this research.
