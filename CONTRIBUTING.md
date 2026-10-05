# Contributing

## Current policy: unsolicited pull requests are not accepted

Obscurize is developed by a single author. Pull requests from outside the
project are **not** being accepted at this time, and open PRs may be closed
without review. This is not a judgment on the quality of the contribution.

There is a licensing reason for the policy, and it is worth stating plainly so
it does not read as unfriendly:

Obscurize code is also used in a separately licensed commercial product. To
keep that possible, the project needs a clear, single chain of copyright
ownership. If an outside contribution were merged without a signed contributor
license agreement, the author of that contribution would retain copyright in
it, and the project could no longer license the affected code into a
commercial product without their permission. That contamination is easy to
create one merge at a time and very difficult to unwind later — it generally
means tracking down every past contributor for retroactive permission, or
reverting and rewriting their work.

So the policy is deliberately closed until a CLA is in place, rather than open
and quietly accruing a problem.

## What is welcome right now

- **Bug reports.** Open an issue. Reproduction steps, Windows build number,
  architecture, and the relevant hook or process involved are all useful.
- **Security issues.** Please report privately rather than in a public issue —
  use GitHub's private vulnerability reporting on this repository.
- **Detection and evasion findings.** If a VM-detection technique defeats
  Obscurize's current coverage, that is valuable even without a patch. A
  description of the check is enough; it does not need to come with code.
- **Compatibility reports.** Processes that crash, hang, or misbehave under
  injection, especially anything not already in the exclusion list.
- **Documentation corrections.** Open an issue describing the error.

Describing a fix in an issue is fine and welcome. Please do not attach a patch
or diff and ask for it to be merged — if the fix is adopted it will be
reimplemented independently, so that authorship stays unambiguous.

## If this policy changes

Should the project open to outside contributions, a contributor license
agreement will be required before any merge, granting the licensor rights
broad enough to license contributed code under both the
[PolyForm Shield License](LICENSE) and commercial terms. A `DCO` sign-off alone
would not be sufficient, because it certifies origin without granting the
relicensing rights the project needs.

Until then: issues yes, pull requests no.

## Third-party code

Obscurize vendors and links MIT-licensed third-party components — see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Please do not open pull
requests against the vendored `r77-rootkit/` tree; report upstream issues to
<https://github.com/bytecode77/r77-rootkit> instead.
