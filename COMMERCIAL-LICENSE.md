# Commercial Licensing

Obscurize Community Edition is distributed under the
[PolyForm Shield License 1.0.0](LICENSE). Shield permits essentially every use
**except** providing a product that competes with Obscurize or with a product
the licensor provides using Obscurize.

If the Noncompete section blocks what you want to do, a separate commercial
license is available. The Shield terms are not intended as a wall — they are
intended as a gate. Ask.

## You do not need a commercial license to

- Run Obscurize on your own machines, at home or at work, at any scale.
- Run Obscurize across your organization's endpoints, however large the
  organization, including as part of a paid internal security program.
- Modify it, build it yourself, and deploy your modified build internally.
- Use it in malware analysis, honeypot, research, teaching, or CTF work.
- Publish research, blog posts, talks, or detection content about it.
- Use it as a tool while delivering security services to a client — incident
  response, malware analysis, red/blue team engagements, consulting — where
  the deliverable is your service, not a product built on Obscurize.
- Fork it publicly and develop improvements, so long as the fork is not
  offered as a substitute for Obscurize or for an Obscurize product.

Being a large company, a commercial entity, or a paying security team does not
by itself require a license. Competing does.

## You do need a commercial license to

- Embed Obscurize, in whole or in part, in a product you sell, license, or
  otherwise provide to others — including EDR, XDR, AV, EPP, sandboxing,
  deception, or anti-analysis products.
- Ship Obscurize-derived code inside a commercial agent, appliance, or SDK.
- Offer a hosted or managed service whose function is substantially what
  Obscurize does.
- Distribute a rebranded or white-labeled build of Obscurize.
- Provide a free product or free tier that functions as a practical substitute
  for Obscurize or for an Obscurize product. Under the Competition section,
  charging nothing does not place a competing product outside the restriction.

If you are unsure which side of the line you are on, that is a reasonable
position to be in and worth a short conversation rather than a guess. The
licensor would rather answer the question than discover the answer later.

## What is available

- **OEM / embedding license** — rights to incorporate Community Edition code
  into a commercial product, with terms negotiated per use case.
- **Obscurize Enterprise Edition** — a separate, commercially licensed product
  with a kernel-mode (Ring 0) agent covering CPUID and RDTSC timing checks that
  userland hooking cannot reach, under a code-signed driver. Licensed
  independently of this repository.

## Earlier MIT-licensed versions

Releases up to and including `1.9.0_Release` were published under the MIT
License and remain available under those terms. The MIT grant on those
versions is perpetual and is not affected by this document or by the current
license. See [LICENSE-MIT-HISTORICAL](LICENSE-MIT-HISTORICAL).

The PolyForm Shield terms apply to everything after that point, including the
multi-agent management console and subsequent agent development.

## How to make an inquiry

Open an issue at
<https://github.com/fluffybunnies-h4x/Obscurize/issues> titled
"Commercial license inquiry". You do not need to disclose confidential product
details in a public issue — say that you have an inquiry and a private channel
will be arranged.

Please include, to whatever extent you can share it publicly:

1. Your organization.
2. What you want to build or ship, and which parts of Obscurize it would use.
3. Whether you need source, binaries, or both.
4. Distribution scale and target market.

## Note

This document is a plain-English summary offered as a convenience. The
[LICENSE](LICENSE) file controls. Where this summary and the license text
disagree, the license text governs, and neither is a substitute for your own
legal advice.
