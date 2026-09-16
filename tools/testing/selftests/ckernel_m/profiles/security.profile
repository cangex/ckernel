profile ckm_s_implicit_deny { file, capability, change_profile, }
profile ckm_s_allow { file, capability, change_profile, signal (send, receive), }
profile ckm_s_deny { file, capability, change_profile, deny signal (send, receive) set=(usr1), }
profile ckm_s_audit { file, capability, audit signal (send, receive), }
