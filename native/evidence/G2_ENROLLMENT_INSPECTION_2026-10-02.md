# G2 interrupted enrollment inspection checkpoint

The installed-root `admin-checkpoint-enrollment-inspect` source command now
reports retained parent intent, parent Name/profile match, the two fixed TPM
handle occupancy results and pending/final directory presence. It classifies
unbound parent intent, bound parent without a proposal, uncertain NV write or
publication, and conflict states. An unsafe or malformed private intent is
refused before TPM observation. It never retries provisioning, unseals a secret,
removes files or changes TPM state. Its observation digest is not attestation,
authorization or an implemented recovery decision.

The complete bounded native regression, including the software-TPM parent
Name/profile match and mismatch checks, passed at
`D:\LumaOS-builds\g2-native-seal-targeted-20261002-09`. Its frozen source
manifest SHA-256 is
`1855209fdf7b3700af76f2742edb9afaa811c98b5f664b07c534302ef3821d51`;
the log SHA-256 is
`9f0d455cb2f4f8dcee71b126ebef94a0152f5597b3962a5380028f3aeec055aa`.
The final stricter conflict classification then passed 11 selected ordinary
enrollment tests, formatting and a warning-clean native build at
`D:\LumaOS-builds\g2-enrollment-inspection-targeted-20261002-01`. Its frozen
source manifest SHA-256 is
`fab73aac2762ff8e9bf9c00029504d62850f9c1991219c8d6dcd7af58bda25ed`;
the log SHA-256 is
`8173b3a335f7ee8e38071e7091ddb5fca589b92f98c1b2277300dd02b9f41104`.

These are source/disposable-TPM checks, not an installed-image interruption
test. Reviewed recovery of a parent allocated before its Name was durably
recorded, a sealed proposal prepared before an uncertain NV write, and final
publication remains unimplemented. No deletion, reset or new allocation is
authorized by an inspection phase. The G2 stage and product Admin service
remain incomplete.
