# Changelog

## [0.3.0](https://github.com/panoptiorg/panopticode/compare/v0.2.0...v0.3.0) (2026-10-18)


### Features

* --fail-on &lt;class,...|any&gt; exits 3 when a finding matches ([5fed8da](https://github.com/panoptiorg/panopticode/commit/5fed8dadade8c113dc2424cec1c7b9f803222551))
* hops carry col; the source hop carries the source function's location ([5fed8da](https://github.com/panoptiorg/panopticode/commit/5fed8dadade8c113dc2424cec1c7b9f803222551))
* inert-rule warnings collapse into one line; --verbose lists them ([5fed8da](https://github.com/panoptiorg/panopticode/commit/5fed8dadade8c113dc2424cec1c7b9f803222551))
* optional [severity] catalog table sets the SARIF level per sink class ([5fed8da](https://github.com/panoptiorg/panopticode/commit/5fed8dadade8c113dc2424cec1c7b9f803222551))
* route.fingerprint, a route id without line numbers, for baselines across commits ([5fed8da](https://github.com/panoptiorg/panopticode/commit/5fed8dadade8c113dc2424cec1c7b9f803222551))
* taint --format text|sarif; SARIF 2.1.0 with each route as a code flow ([5fed8da](https://github.com/panoptiorg/panopticode/commit/5fed8dadade8c113dc2424cec1c7b9f803222551))
* the example catalog is built into the binary; --catalog is optional ([5fed8da](https://github.com/panoptiorg/panopticode/commit/5fed8dadade8c113dc2424cec1c7b9f803222551))


### Bug Fixes

* a --cgf directory with no .pb files is an error instead of zero findings ([5fed8da](https://github.com/panoptiorg/panopticode/commit/5fed8dadade8c113dc2424cec1c7b9f803222551))
* default leaf for each call target without a summary; CallSite.target_fqns ([#7](https://github.com/panoptiorg/panopticode/issues/7)) ([edde625](https://github.com/panoptiorg/panopticode/commit/edde625e6efb20d497922a57d70c2d51f80d487c))
* extract and impact name a missing pc-fe ([5fed8da](https://github.com/panoptiorg/panopticode/commit/5fed8dadade8c113dc2424cec1c7b9f803222551))

## [0.2.0](https://github.com/panoptiorg/panopticode/compare/v0.1.0...v0.2.0) (2026-10-08)


### Features

* link HTTP client calls to routes; source write-back ports and sink argument filters ([#3](https://github.com/panoptiorg/panopticode/issues/3)) ([d506f3f](https://github.com/panoptiorg/panopticode/commit/d506f3f6e44e8b4a506199e080649c9645c3d1ee))

## 0.1.0 (2026-10-04)


### Features

* initial release ([d0fd50d](https://github.com/panoptiorg/panopticode/commit/d0fd50dc1476a25b99b0a7b27a1bf0a87182b61d))
