# Native behavior fixtures only; no cached qualification is assumed.
abi <abi/3.0>,
profile ckm_net_allow flags=(attach_disconnected) {
  capability,
  change_profile,
  /** rwmlk,
  network inet stream,
  network inet dgram,
}
profile ckm_net_deny flags=(attach_disconnected) {
  capability,
  change_profile,
  /** rwmlk,
  deny network inet stream,
  deny network inet dgram,
}
profile ckm_net_audit flags=(attach_disconnected) {
  capability,
  change_profile,
  /** rwmlk,
  audit network inet stream,
  audit network inet dgram,
}
