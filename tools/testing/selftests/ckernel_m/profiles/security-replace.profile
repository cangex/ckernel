profile ckm_s_reload {
  file,
  capability,
  deny signal (send, receive) set=(usr1),
  deny /tmp/ckm-security-secret r,
}
